(module
  ;; The host currently supplies object bodies but not their type hashes, schema
  ;; versions, IDs, or owners. This module consequently validates the complete
  ;; self-describing body frame; node-core separately authenticates the
  ;; sender-owned source, enforces the committed destination policy, and freezes
  ;; object metadata including both owners across each update.
  (import "env" "get_object_count" (func $get_object_count (result i32)))
  (import "env" "get_object_data_len" (func $get_object_data_len (param i32) (result i32)))
  (import "env" "read_object_data" (func $read_object_data (param i32 i32 i32 i32) (result i32)))
  (import "env" "write_object_data" (func $write_object_data (param i32 i32 i32) (result i32)))
  (import "env" "emit_event" (func $emit_event (param i32 i32 i32 i32) (result i32)))
  (import "env" "get_args_len" (func $get_args_len (result i32)))
  (import "env" "read_args" (func $read_args (param i32 i32 i32) (result i32)))
  (import "env" "abort" (func $abort (param i32 i32)))

  (memory (export "memory") 1)

  ;; Memory layout:
  ;;     0..76   source body
  ;;    96..172  destination body
  ;;   192..216  transfer arguments
  ;;   256..346  transfer event
  ;;   384..427  event type tag
  ;;   512..534  deterministic failure reason
  (data (i32.const 384) "sunrise.devnet.asset_account.transferred.v1")
  (data (i32.const 512) "invalid asset transfer")

  (func $fail
    (call $abort (i32.const 512) (i32.const 22))
    unreachable)

  ;; Validate every constant byte in a 76-byte CanonicalStruct(0xF001, v1):
  ;; header + field 1 header, then the field 2 and field 3 headers. The three
  ;; declared values occupy the only remaining bytes.
  (func $check_body (param $ptr i32)
    (if
      (i64.ne
        (i64.load (local.get $ptr))
        (i64.const 0x0001f00145524e53))
      (then (call $fail)))
    (if
      (i64.ne
        (i64.load offset=8 (local.get $ptr))
        (i64.const 0x0000002000010003))
      (then (call $fail)))
    (if
      (i32.ne
        (i32.load16_u offset=48 (local.get $ptr))
        (i32.const 2))
      (then (call $fail)))
    (if
      (i32.ne
        (i32.load offset=50 (local.get $ptr))
        (i32.const 8))
      (then (call $fail)))
    (if
      (i32.ne
        (i32.load16_u offset=62 (local.get $ptr))
        (i32.const 3))
      (then (call $fail)))
    (if
      (i32.ne
        (i32.load offset=64 (local.get $ptr))
        (i32.const 8))
      (then (call $fail))))

  (func (export "transfer")
    (local $amount i64)
    (local $source_balance i64)
    (local $destination_balance i64)
    (local $new_source_balance i64)
    (local $new_destination_balance i64)
    (local $source_sequence i64)
    (local $destination_sequence i64)

    (if
      (i32.ne (call $get_object_count) (i32.const 2))
      (then (call $fail)))
    (if
      (i32.ne (call $get_object_data_len (i32.const 0)) (i32.const 76))
      (then (call $fail)))
    (if
      (i32.ne (call $get_object_data_len (i32.const 1)) (i32.const 76))
      (then (call $fail)))
    (if
      (i32.ne
        (call $read_object_data
          (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 76))
        (i32.const 76))
      (then (call $fail)))
    (if
      (i32.ne
        (call $read_object_data
          (i32.const 1) (i32.const 0) (i32.const 96) (i32.const 76))
        (i32.const 76))
      (then (call $fail)))

    (call $check_body (i32.const 0))
    (call $check_body (i32.const 96))

    ;; Asset IDs must match exactly.
    (if
      (i64.ne (i64.load offset=16 (i32.const 0)) (i64.load offset=16 (i32.const 96)))
      (then (call $fail)))
    (if
      (i64.ne (i64.load offset=24 (i32.const 0)) (i64.load offset=24 (i32.const 96)))
      (then (call $fail)))
    (if
      (i64.ne (i64.load offset=32 (i32.const 0)) (i64.load offset=32 (i32.const 96)))
      (then (call $fail)))
    (if
      (i64.ne (i64.load offset=40 (i32.const 0)) (i64.load offset=40 (i32.const 96)))
      (then (call $fail)))

    ;; CanonicalStruct(0xF002, v1) has exactly one u64 field.
    (if
      (i32.ne (call $get_args_len) (i32.const 24))
      (then (call $fail)))
    (if
      (i32.ne
        (call $read_args (i32.const 0) (i32.const 192) (i32.const 24))
        (i32.const 24))
      (then (call $fail)))
    (if
      (i64.ne
        (i64.load (i32.const 192))
        (i64.const 0x0001f00245524e53))
      (then (call $fail)))
    (if
      (i64.ne
        (i64.load offset=8 (i32.const 192))
        (i64.const 0x0000000800010001))
      (then (call $fail)))

    (local.set $amount (i64.load offset=16 (i32.const 192)))
    (local.set $source_balance (i64.load offset=54 (i32.const 0)))
    (local.set $destination_balance (i64.load offset=54 (i32.const 96)))
    (local.set $source_sequence (i64.load offset=68 (i32.const 0)))
    (local.set $destination_sequence (i64.load offset=68 (i32.const 96)))

    (if (i64.eqz (local.get $amount)) (then (call $fail)))
    (if
      (i64.lt_u (local.get $source_balance) (local.get $amount))
      (then (call $fail)))
    (local.set $new_source_balance
      (i64.sub (local.get $source_balance) (local.get $amount)))
    (local.set $new_destination_balance
      (i64.add (local.get $destination_balance) (local.get $amount)))
    (if
      (i64.lt_u
        (local.get $new_destination_balance)
        (local.get $destination_balance))
      (then (call $fail)))
    (if
      (i64.eq (local.get $source_sequence) (i64.const -1))
      (then (call $fail)))
    (if
      (i64.eq (local.get $destination_sequence) (i64.const -1))
      (then (call $fail)))

    ;; Patch only declared values in the already-validated canonical bodies.
    (i64.store offset=54 (i32.const 0) (local.get $new_source_balance))
    (i64.store offset=68
      (i32.const 0)
      (i64.add (local.get $source_sequence) (i64.const 1)))
    (i64.store offset=54 (i32.const 96) (local.get $new_destination_balance))
    (i64.store offset=68
      (i32.const 96)
      (i64.add (local.get $destination_sequence) (i64.const 1)))

    ;; Build CanonicalStruct(0xF003, v1) in zero-initialized memory.
    (i64.store
      (i32.const 256)
      (i64.const 0x0001f00345524e53))
    (i64.store offset=8
      (i32.const 256)
      (i64.const 0x0000002000010004))
    (i64.store offset=16 (i32.const 256) (i64.load offset=16 (i32.const 0)))
    (i64.store offset=24 (i32.const 256) (i64.load offset=24 (i32.const 0)))
    (i64.store offset=32 (i32.const 256) (i64.load offset=32 (i32.const 0)))
    (i64.store offset=40 (i32.const 256) (i64.load offset=40 (i32.const 0)))
    (i32.store16 offset=48 (i32.const 256) (i32.const 2))
    (i32.store offset=50 (i32.const 256) (i32.const 8))
    (i64.store offset=54 (i32.const 256) (local.get $amount))
    (i32.store16 offset=62 (i32.const 256) (i32.const 3))
    (i32.store offset=64 (i32.const 256) (i32.const 8))
    (i64.store offset=68 (i32.const 256) (local.get $new_source_balance))
    (i32.store16 offset=76 (i32.const 256) (i32.const 4))
    (i32.store offset=78 (i32.const 256) (i32.const 8))
    (i64.store offset=82 (i32.const 256) (local.get $new_destination_balance))

    (if
      (i32.ne
        (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 76))
        (i32.const 0))
      (then (call $fail)))
    (if
      (i32.ne
        (call $write_object_data (i32.const 1) (i32.const 96) (i32.const 76))
        (i32.const 0))
      (then (call $fail)))
    (if
      (i32.ne
        (call $emit_event
          (i32.const 384) (i32.const 43) (i32.const 256) (i32.const 90))
        (i32.const 0))
      (then (call $fail)))))
