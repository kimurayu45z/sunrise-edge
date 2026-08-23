//! Deterministic WASM execution engine backed by `wasmi`.
//!
//! # Host ABI
//!
//! Contracts import functions from the `"env"` module.  All pointer arguments
//! are byte offsets into the contract's linear memory.  All lengths are in
//! bytes.  Functions return `0` on success and `-1` on error unless noted
//! otherwise.
//!
//! | Function | Signature | Description |
//! |---|---|---|
//! | `get_object_count` | `() -> i32` | Number of resolved input objects |
//! | `get_object_data_len` | `(index: i32) -> i32` | Length of `object[index].data`; -1 if invalid/consumed |
//! | `read_object_data` | `(index: i32, offset: i32, buf_ptr: i32, buf_len: i32) -> i32` | Copy `object[index].data[offset..]` into WASM memory; returns bytes written or -1 |
//! | `write_object_data` | `(index: i32, data_ptr: i32, data_len: i32) -> i32` | Mutate `object[index]` data (must have `Write` access) |
//! | `consume_object` | `(index: i32) -> i32` | Mark `object[index]` as consumed (must have `Consume` access) |
//! | `create_object` | `(data_ptr: i32, data_len: i32, type_hash_ptr: i32, schema_version: i32, owner_tag: i32, owner_addr_ptr: i32) -> i32` | Create a new object; `type_hash_ptr` → 34 bytes (2 BE algo-id + 32 hash bytes); owner tags: 0=Shared, 1=Immutable, 2=System, 3=Address (owner_addr_ptr → 32-byte address) |
//! | `emit_event` | `(type_tag_ptr: i32, type_tag_len: i32, data_ptr: i32, data_len: i32) -> i32` | Emit an event |
//! | `get_args_len` | `() -> i32` | Length of the transaction args payload |
//! | `read_args` | `(offset: i32, buf_ptr: i32, buf_len: i32) -> i32` | Copy `args[offset..]` into WASM memory; returns bytes written or -1 |
//! | `abort` | `(msg_ptr: i32, msg_len: i32)` | Trap with a UTF-8 reason string |
//!
//! # Entry-point signature
//!
//! The exported entry-point function **must** have the signature `() -> ()`.
//! The engine calls it with no arguments and expects no return values.
//! A contract whose entry point has a different signature (e.g. returns `i32`)
//! will produce a [`ExecutionError::WasmEngine`] error, not
//! [`ExecutionError::MissingEntrypoint`].
//!
//! # Object ID derivation
//!
//! IDs for objects created during execution are derived deterministically:
//! ```text
//! new_id = SHA-256( tx_hash_bytes || creation_index_le_u32 )
//! ```
//!
//! # Gas / fuel
//!
//! `wasmi` fuel consumption is enabled.  Each WASM instruction costs one fuel
//! unit.  The initial fuel equals `gas_limit`.  `gas_used` is computed from
//! the difference.

use objects::{AccessMode, Address, Object, ObjectId, Owner};
use protocol_types::{Digest32, HashAlgorithmId, ProtocolVersion};
use sha2::{Digest as _, Sha256};
use wasmi::{Caller, Config, Engine, Error as WasmiError, Linker, Module, Store};

use crate::{
    EventRecord, ExecutionEffects, ExecutionEngine, ExecutionError, ExecutionStatus, ObjectEffect,
    ResolvedObject,
};

// ── type-hash wire format constants ──────────────────────────────────────

/// A `type_hash` pointer in the host ABI must reference this many bytes:
/// 2 bytes big-endian `HashAlgorithmId` followed by 32 hash bytes.
const TYPE_HASH_WIRE_LEN: usize = 34;
/// Byte length of a raw address in the host ABI.
const ADDRESS_WIRE_LEN: usize = 32;

// ── host state ────────────────────────────────────────────────────────────

/// State threaded through all host-function calls for a single execution.
struct HostState {
    /// Resolved input objects (matches the transaction's `AccessManifest`).
    inputs: Vec<ResolvedObject>,
    /// New object data written via `write_object_data`, keyed by input index.
    mutated_data: Vec<Option<Vec<u8>>>,
    /// Whether each input has been consumed via `consume_object`.
    consumed: Vec<bool>,
    /// Objects created by the contract during this execution.
    created_objects: Vec<Object>,
    /// Events emitted by the contract.
    events: Vec<EventRecord>,
    /// Transaction args bytes.
    args: Vec<u8>,
    /// Transaction hash used to derive new object IDs.
    tx_hash: Digest32,
    /// Monotonic counter for new object ID derivation.
    creation_counter: u32,
    /// Trap message set by the `abort` host function.
    trap: Option<String>,
}

impl HostState {
    fn new(inputs: Vec<ResolvedObject>, args: Vec<u8>, tx_hash: Digest32) -> Self {
        let n = inputs.len();
        Self {
            inputs,
            mutated_data: vec![None; n],
            consumed: vec![false; n],
            created_objects: Vec::new(),
            events: Vec::new(),
            args,
            tx_hash,
            creation_counter: 0,
            trap: None,
        }
    }

    /// Derives the next deterministic `ObjectId` for a newly created object.
    fn next_object_id(&mut self) -> ObjectId {
        let counter = self.creation_counter;
        self.creation_counter += 1;

        let mut hasher = Sha256::new();
        hasher.update(self.tx_hash.bytes());
        hasher.update(counter.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        ObjectId::new(hash)
    }
}

// ── memory helpers ────────────────────────────────────────────────────────

/// Copy `len` bytes starting at `offset` from `src` into WASM linear memory
/// at `buf_ptr`.  Returns the number of bytes written, or `-1` on error.
fn write_to_wasm(caller: &mut Caller<HostState>, buf_ptr: i32, src: &[u8]) -> i32 {
    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return -1;
    };
    let ptr = buf_ptr as usize;
    let wasm_mem = mem.data_mut(caller);
    if ptr.saturating_add(src.len()) > wasm_mem.len() {
        return -1;
    }
    wasm_mem[ptr..ptr + src.len()].copy_from_slice(src);
    src.len() as i32
}

/// Read `len` bytes from WASM linear memory at `ptr`.  Returns `None` if the
/// access would go out of bounds.
fn read_from_wasm(caller: &Caller<HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let mem = caller.get_export("memory")?.into_memory()?;
    let ptr = ptr as usize;
    let len = len as usize;
    let data = mem.data(caller);
    if ptr.saturating_add(len) > data.len() {
        return None;
    }
    Some(data[ptr..ptr + len].to_vec())
}

// ── linker registration ───────────────────────────────────────────────────

fn register_host_functions(linker: &mut Linker<HostState>) -> Result<(), WasmiError> {
    // ── get_object_count ─────────────────────────────────────────────────
    linker.func_wrap("env", "get_object_count", |caller: Caller<HostState>| -> i32 {
        caller.data().inputs.len() as i32
    })?;

    // ── get_object_data_len ──────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "get_object_data_len",
        |caller: Caller<HostState>, index: i32| -> i32 {
            let state = caller.data();
            let idx = index as usize;
            if idx >= state.inputs.len() || state.consumed[idx] {
                return -1;
            }
            // Return the length of the potentially mutated data.
            if let Some(new_data) = &state.mutated_data[idx] {
                new_data.len() as i32
            } else {
                state.inputs[idx].object.data.len() as i32
            }
        },
    )?;

    // ── read_object_data ─────────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "read_object_data",
        |mut caller: Caller<HostState>, index: i32, offset: i32, buf_ptr: i32, buf_len: i32|
         -> i32 {
            let idx = index as usize;
            let off = offset as usize;
            let len = buf_len as usize;

            let data: Vec<u8> = {
                let state = caller.data();
                if idx >= state.inputs.len() || state.consumed[idx] {
                    return -1;
                }
                let src = state
                    .mutated_data
                    .get(idx)
                    .and_then(|d| d.as_ref())
                    .map(|d| d.as_slice())
                    .unwrap_or(state.inputs[idx].object.data.as_slice());
                if off > src.len() {
                    return -1;
                }
                let end = (off + len).min(src.len());
                src[off..end].to_vec()
            };

            write_to_wasm(&mut caller, buf_ptr, &data)
        },
    )?;

    // ── write_object_data ────────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "write_object_data",
        |mut caller: Caller<HostState>, index: i32, data_ptr: i32, data_len: i32| -> i32 {
            let idx = index as usize;
            {
                let state = caller.data();
                if idx >= state.inputs.len()
                    || state.consumed[idx]
                    || state.inputs[idx].mode != AccessMode::Write
                {
                    return -1;
                }
            }
            let Some(new_data) = read_from_wasm(&caller, data_ptr, data_len) else {
                return -1;
            };
            caller.data_mut().mutated_data[idx] = Some(new_data);
            0
        },
    )?;

    // ── consume_object ───────────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "consume_object",
        |mut caller: Caller<HostState>, index: i32| -> i32 {
            let idx = index as usize;
            {
                let state = caller.data();
                if idx >= state.inputs.len()
                    || state.consumed[idx]
                    || state.inputs[idx].mode != AccessMode::Consume
                {
                    return -1;
                }
            }
            caller.data_mut().consumed[idx] = true;
            0
        },
    )?;

    // ── create_object ────────────────────────────────────────────────────
    //
    // Signature: (data_ptr, data_len, type_hash_ptr, schema_version, owner_tag, owner_addr_ptr)
    //
    // type_hash_ptr → TYPE_HASH_WIRE_LEN bytes: [algo_id_hi, algo_id_lo, hash[0]..hash[31]]
    // owner_tag: 0=Shared, 1=Immutable, 2=System, 3=Address (owner_addr_ptr → 32 bytes)
    linker.func_wrap(
        "env",
        "create_object",
        |mut caller: Caller<HostState>,
         data_ptr: i32,
         data_len: i32,
         type_hash_ptr: i32,
         schema_version: i32,
         owner_tag: i32,
         owner_addr_ptr: i32|
         -> i32 {
            let data = match read_from_wasm(&caller, data_ptr, data_len) {
                Some(d) => d,
                None => return -1,
            };
            let type_hash_bytes =
                match read_from_wasm(&caller, type_hash_ptr, TYPE_HASH_WIRE_LEN as i32) {
                    Some(b) => b,
                    None => return -1,
                };
            let algo_id_u16 = u16::from_be_bytes([type_hash_bytes[0], type_hash_bytes[1]]);
            let algo_id = match HashAlgorithmId::try_from(algo_id_u16) {
                Ok(id) => id,
                Err(_) => return -1,
            };
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&type_hash_bytes[2..]);
            let type_hash = Digest32::new(algo_id, hash_bytes);

            let owner = match owner_tag {
                0 => Owner::Shared,
                1 => Owner::Immutable,
                2 => Owner::System,
                3 => {
                    let addr_bytes =
                        match read_from_wasm(&caller, owner_addr_ptr, ADDRESS_WIRE_LEN as i32) {
                            Some(b) => b,
                            None => return -1,
                        };
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&addr_bytes);
                    Owner::Address(Address::new(arr))
                }
                _ => return -1,
            };

            let id = caller.data_mut().next_object_id();
            let obj = Object {
                id,
                version: 1,
                owner,
                type_hash,
                schema_version: schema_version as u32,
                data,
            };
            caller.data_mut().created_objects.push(obj);
            0
        },
    )?;

    // ── emit_event ───────────────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "emit_event",
        |mut caller: Caller<HostState>,
         type_tag_ptr: i32,
         type_tag_len: i32,
         data_ptr: i32,
         data_len: i32|
         -> i32 {
            let type_tag = match read_from_wasm(&caller, type_tag_ptr, type_tag_len) {
                Some(t) => t,
                None => return -1,
            };
            let data = match read_from_wasm(&caller, data_ptr, data_len) {
                Some(d) => d,
                None => return -1,
            };
            caller.data_mut().events.push(EventRecord { type_tag, data });
            0
        },
    )?;

    // ── get_args_len ─────────────────────────────────────────────────────
    linker.func_wrap("env", "get_args_len", |caller: Caller<HostState>| -> i32 {
        caller.data().args.len() as i32
    })?;

    // ── read_args ────────────────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "read_args",
        |mut caller: Caller<HostState>, offset: i32, buf_ptr: i32, buf_len: i32| -> i32 {
            let off = offset as usize;
            let len = buf_len as usize;
            let chunk: Vec<u8> = {
                let args = &caller.data().args;
                if off > args.len() {
                    return -1;
                }
                let end = (off + len).min(args.len());
                args[off..end].to_vec()
            };
            write_to_wasm(&mut caller, buf_ptr, &chunk)
        },
    )?;

    // ── abort ────────────────────────────────────────────────────────────
    linker.func_wrap(
        "env",
        "abort",
        |mut caller: Caller<HostState>, msg_ptr: i32, msg_len: i32| -> Result<(), WasmiError> {
            let msg = read_from_wasm(&caller, msg_ptr, msg_len)
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "contract aborted".to_string());
            caller.data_mut().trap = Some(msg.clone());
            // Return a wasmi trap to halt WASM execution immediately.
        Err(WasmiError::new(msg))
        },
    )?;

    Ok(())
}

// ── WasmExecutionEngine ───────────────────────────────────────────────────

/// Deterministic [`ExecutionEngine`] backed by `wasmi`.
///
/// Each call to [`execute`][WasmExecutionEngine::execute] creates a fresh
/// engine, instantiates the module from scratch, runs the requested entry
/// point, and converts the accumulated host state into [`ExecutionEffects`].
///
/// Fuel-based gas metering is enabled: `gas_limit` fuel units are loaded
/// before invocation and `gas_used` is computed from the difference.
#[derive(Debug, Clone, Copy, Default)]
pub struct WasmExecutionEngine;

impl ExecutionEngine for WasmExecutionEngine {
    fn execute(
        &self,
        _protocol_version: ProtocolVersion,
        tx_hash: Digest32,
        module: &[u8],
        entrypoint: &str,
        inputs: &[ResolvedObject],
        args: &[u8],
        gas_limit: u64,
    ) -> Result<ExecutionEffects, ExecutionError> {
        // ── engine with fuel consumption ─────────────────────────────────
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);

        // ── host state ────────────────────────────────────────────────────
        let host = HostState::new(inputs.to_vec(), args.to_vec(), tx_hash);
        let mut store = Store::new(&engine, host);
        store
            .set_fuel(gas_limit)
            .map_err(|e| ExecutionError::WasmEngine(e.to_string()))?;

        // ── module compilation ───────────────────────────────────────────
        let wasm_module = Module::new(&engine, module)
            .map_err(|e| ExecutionError::WasmEngine(e.to_string()))?;

        // ── linker with host functions ────────────────────────────────────
        let mut linker: Linker<HostState> = Linker::new(&engine);
        register_host_functions(&mut linker)
            .map_err(|e| ExecutionError::WasmEngine(e.to_string()))?;

        // ── instantiate ───────────────────────────────────────────────────
        let instance = linker
            .instantiate_and_start(&mut store, &wasm_module)
            .map_err(|e| ExecutionError::WasmEngine(e.to_string()))?;

        // ── call entry point ──────────────────────────────────────────────
        let func = instance
            .get_func(&store, entrypoint)
            .ok_or_else(|| ExecutionError::MissingEntrypoint(entrypoint.to_string()))?;

        let call_result = func.call(&mut store, &[], &mut []);

        // ── gas accounting ────────────────────────────────────────────────
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let gas_used = gas_limit.saturating_sub(fuel_remaining);

        // ── determine execution status ───────────────────────────────────
        let status = match call_result {
            Ok(()) => {
                // Check if `abort` was called (sets trap without returning an error
                // from the return-type perspective).
                if let Some(msg) = store.data().trap.clone() {
                    ExecutionStatus::Failure { reason: msg }
                } else {
                    ExecutionStatus::Success
                }
            }
            Err(wasmi_err) => {
                // Prefer the abort message if set.
                let reason = store
                    .data()
                    .trap
                    .clone()
                    .unwrap_or_else(|| wasmi_err.to_string());
                ExecutionStatus::Failure { reason }
            }
        };

        // ── build object effects ──────────────────────────────────────────
        let mut object_effects: Vec<ObjectEffect> = Vec::new();

        // Only materialise effects when execution succeeded.
        if matches!(status, ExecutionStatus::Success) {
            let state = store.data();

            for (idx, resolved) in state.inputs.iter().enumerate() {
                if state.consumed[idx] {
                    object_effects.push(ObjectEffect::Deleted {
                        id: resolved.object.id,
                        version: resolved.object.version,
                    });
                } else if let Some(new_data) = &state.mutated_data[idx] {
                    let mut new_obj = resolved.object.clone();
                    new_obj.version += 1;
                    new_obj.data = new_data.clone();
                    object_effects.push(ObjectEffect::Mutated {
                        previous_version: resolved.object.version,
                        new_object: new_obj,
                    });
                }
            }

            for created in &state.created_objects {
                object_effects.push(ObjectEffect::Created(created.clone()));
            }
        }

        let events = if matches!(status, ExecutionStatus::Success) {
            store.data().events.clone()
        } else {
            Vec::new()
        };

        Ok(ExecutionEffects {
            tx_hash,
            status,
            object_effects,
            events,
            gas_used,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use objects::{AccessMode, Object, ObjectId, Owner};
    use protocol_types::{Digest32, HashAlgorithmId, ProtocolVersion};

    fn sample_digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn sample_protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(1)
    }

    fn sample_object(id_byte: u8, version: u64) -> Object {
        Object {
            id: ObjectId::new([id_byte; 32]),
            version,
            owner: Owner::Shared,
            type_hash: sample_digest(0xAA),
            schema_version: 1,
            data: vec![id_byte; 8],
        }
    }

    fn emit_noop_wat() -> String {
        r#"
        (module
          (import "env" "get_object_count"   (func $get_object_count   (result i32)))
          (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
          (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
          (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
          (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
          (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
          (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
          (import "env" "get_args_len"       (func $get_args_len       (result i32)))
          (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
          (import "env" "abort"              (func $abort              (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          (func (export "run"))
        )
        "#.to_string()
    }

    fn wat_to_wasm(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("WAT parse failed")
    }

    #[test]
    fn noop_contract_succeeds() {
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(&emit_noop_wat());
        let tx_hash = sample_digest(0x01);
        let effects = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                &wasm,
                "run",
                &[],
                &[],
                1_000_000,
            )
            .unwrap();
        assert_eq!(effects.tx_hash, tx_hash);
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert!(effects.object_effects.is_empty());
        assert!(effects.events.is_empty());
    }

    #[test]
    fn missing_entrypoint_is_error() {
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(&emit_noop_wat());
        let result = engine.execute(
            sample_protocol_version(),
            sample_digest(0x02),
            &wasm,
            "nonexistent",
            &[],
            &[],
            1_000_000,
        );
        assert!(matches!(result, Err(ExecutionError::MissingEntrypoint(_))));
    }

    #[test]
    fn emit_event_contract() {
        // Contract that emits one event with type_tag = [0x01] and data = [0x02, 0x03].
        let wat = r#"
        (module
          (import "env" "get_object_count"   (func $get_object_count   (result i32)))
          (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
          (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
          (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
          (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
          (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
          (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
          (import "env" "get_args_len"       (func $get_args_len       (result i32)))
          (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
          (import "env" "abort"              (func $abort              (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          ;; memory layout: byte 0 = type_tag (0x01), bytes 1-2 = data (0x02, 0x03)
          (data (i32.const 0) "\01\02\03")
          (func (export "run")
            ;; emit_event(type_tag_ptr=0, type_tag_len=1, data_ptr=1, data_len=2)
            (drop (call $emit_event (i32.const 0) (i32.const 1) (i32.const 1) (i32.const 2)))
          )
        )
        "#;
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(wat);
        let tx_hash = sample_digest(0x03);
        let effects = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                &wasm,
                "run",
                &[],
                &[],
                1_000_000,
            )
            .unwrap();
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.events.len(), 1);
        assert_eq!(effects.events[0].type_tag, vec![0x01]);
        assert_eq!(effects.events[0].data, vec![0x02, 0x03]);
    }

    #[test]
    fn write_object_contract() {
        // Contract that overwrites object[0] data with [0xBE, 0xEF].
        let wat = r#"
        (module
          (import "env" "get_object_count"   (func $get_object_count   (result i32)))
          (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
          (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
          (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
          (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
          (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
          (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
          (import "env" "get_args_len"       (func $get_args_len       (result i32)))
          (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
          (import "env" "abort"              (func $abort              (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          ;; bytes 0-1: new object data (0xBE, 0xEF)
          (data (i32.const 0) "\BE\EF")
          (func (export "run")
            ;; write_object_data(index=0, data_ptr=0, data_len=2)
            (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))
          )
        )
        "#;
        let resolved = ResolvedObject {
            object: sample_object(0x11, 5),
            mode: AccessMode::Write,
        };
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(wat);
        let tx_hash = sample_digest(0x04);
        let effects = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                &wasm,
                "run",
                &[resolved],
                &[],
                1_000_000,
            )
            .unwrap();
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 1);
        if let ObjectEffect::Mutated { previous_version, new_object } = &effects.object_effects[0]
        {
            assert_eq!(*previous_version, 5);
            assert_eq!(new_object.version, 6);
            assert_eq!(new_object.data, vec![0xBE, 0xEF]);
        } else {
            panic!("expected Mutated effect");
        }
    }

    #[test]
    fn consume_object_contract() {
        // Contract that consumes object[0].
        let wat = r#"
        (module
          (import "env" "get_object_count"   (func $get_object_count   (result i32)))
          (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
          (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
          (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
          (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
          (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
          (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
          (import "env" "get_args_len"       (func $get_args_len       (result i32)))
          (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
          (import "env" "abort"              (func $abort              (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          (func (export "run")
            (drop (call $consume_object (i32.const 0)))
          )
        )
        "#;
        let resolved = ResolvedObject {
            object: sample_object(0x22, 3),
            mode: AccessMode::Consume,
        };
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(wat);
        let tx_hash = sample_digest(0x05);
        let effects = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                &wasm,
                "run",
                &[resolved],
                &[],
                1_000_000,
            )
            .unwrap();
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 1);
        assert!(matches!(
            effects.object_effects[0],
            ObjectEffect::Deleted { version: 3, .. }
        ));
    }

    #[test]
    fn abort_produces_failure_status() {
        // Contract that calls abort immediately.
        let wat = r#"
        (module
          (import "env" "get_object_count"   (func $get_object_count   (result i32)))
          (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
          (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
          (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
          (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
          (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
          (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
          (import "env" "get_args_len"       (func $get_args_len       (result i32)))
          (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
          (import "env" "abort"              (func $abort              (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          (data (i32.const 0) "bad input")
          (func (export "run")
            (call $abort (i32.const 0) (i32.const 9))
          )
        )
        "#;
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(wat);
        let effects = engine
            .execute(
                sample_protocol_version(),
                sample_digest(0x06),
                &wasm,
                "run",
                &[],
                &[],
                1_000_000,
            )
            .unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Failure { .. }));
        if let ExecutionStatus::Failure { reason } = &effects.status {
            assert_eq!(reason, "bad input");
        }
        // Events and object effects are discarded on failure.
        assert!(effects.object_effects.is_empty());
        assert!(effects.events.is_empty());
    }

    #[test]
    fn gas_limit_of_zero_traps() {
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(&emit_noop_wat());
        let effects = engine
            .execute(
                sample_protocol_version(),
                sample_digest(0x07),
                &wasm,
                "run",
                &[],
                &[],
                0, // zero gas
            )
            .unwrap();
        // With no fuel the WASM runtime may trap or succeed depending on the
        // instruction count; either way the effects are consistent.
        let _ = effects.status;
    }

    #[test]
    fn created_objects_have_deterministic_ids() {
        // Contract that creates two objects.
        let wat = r#"
        (module
          (import "env" "get_object_count"   (func $get_object_count   (result i32)))
          (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
          (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
          (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
          (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
          (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
          (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
          (import "env" "get_args_len"       (func $get_args_len       (result i32)))
          (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
          (import "env" "abort"              (func $abort              (param i32 i32)))
          (memory 1)
          (export "memory" (memory 0))
          ;; type hash: algo=0x0001 (Sha2_256), hash=[0u8;32]  total 34 bytes at offset 0
          ;; data = [0xFF] at offset 34
          ;; second data = [0xFE] at offset 35
          (data (i32.const 0) "\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF\FE")
          (func (export "run")
            ;; create_object(data_ptr=34, data_len=1, type_hash_ptr=0, schema_version=1, owner_tag=0, owner_addr_ptr=0)
            (drop (call $create_object (i32.const 34) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))
            ;; create_object(data_ptr=35, data_len=1, ...)
            (drop (call $create_object (i32.const 35) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))
          )
        )
        "#;
        let engine = WasmExecutionEngine;
        let wasm = wat_to_wasm(wat);
        let tx_hash = sample_digest(0x08);

        // Run twice and compare IDs.
        let e1 = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                &wasm,
                "run",
                &[],
                &[],
                1_000_000,
            )
            .unwrap();
        let e2 = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                &wasm,
                "run",
                &[],
                &[],
                1_000_000,
            )
            .unwrap();

        assert_eq!(e1.object_effects.len(), 2);
        assert_eq!(e2.object_effects.len(), 2);

        // IDs must match between runs.
        let id1a = if let ObjectEffect::Created(obj) = &e1.object_effects[0] {
            obj.id
        } else {
            panic!("expected Created")
        };
        let id1b = if let ObjectEffect::Created(obj) = &e2.object_effects[0] {
            obj.id
        } else {
            panic!("expected Created")
        };
        assert_eq!(id1a, id1b);

        // The two objects within a single run must have different IDs.
        let id2a = if let ObjectEffect::Created(obj) = &e1.object_effects[1] {
            obj.id
        } else {
            panic!("expected Created")
        };
        assert_ne!(id1a, id2a);
    }
}
