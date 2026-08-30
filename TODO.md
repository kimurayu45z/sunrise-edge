あなたはRust、分散システム、BFTコンセンサス、WebAssembly、暗号プロトコル、ゼロ知識証明に精通したシニアブロックチェーンエンジニアです。

以下の設計思想に基づく、新しいproduction-grade L1 blockchainを実装してください。

将来のmainnet運用、protocol upgrade、multi-cloud deployment、validator set変更、暗号アルゴリズム移行、state互換性、ZK executionを最初から前提として設計してください。


# 0. Core Philosophy

最重要原則:

"A blockchain node is a state machine, not a process."

従来型Blockchain Nodeのような、

- 常駐daemon
- while(true)
- 常時接続P2P
- persistent WebSocket
- background worker
- RAM上の巨大なmutable state

をprotocolの前提にしてはいけません。

validatorはrequest/event drivenなstate machineとして実装します。

以下のruntime上で同一Node Coreを動作可能にしてください。

- Cloudflare Workers
- Vercel Functions
- Supabase Edge Functions
- AWS Lambda
- Deno Deploy
- Node.js
- native server

Cloudflare Workers等はruntime adapterに過ぎません。
protocol/coreにvendor-specific dependencyを入れてはいけません。


# 1. Fundamental Principles

1. Node is a state machine, not a process
2. Consensus does not require persistent processes
3. Consensus does not require persistent connections
4. Relay / client / schedulerはuntrusted
5. Cloud providerはconsensus trust rootではない
6. Object-centric versioned state
7. ABI-driven concurrency
8. Deterministic WASM execution
9. Protocol upgradeabilityはfirst-class feature
10. Native tokenをprotocol securityの前提にしない
11. Validator bondとvoting powerを分離する
12. Stablecoin-denominated transaction fees
13. Validator rewardはtransaction feesを基本とする
14. Dynamic governance-installed system modules
15. Zero-knowledge proof friendly execution
16. Cryptographic agilityを最初から設計する
17. Hash algorithmはtransaction senderに選択させない
18. Domain separationを全protocol hash/signatureに適用する
19. Global mutable state/global mutexは禁止
20. Massive stateでもserverless execution可能にする


# 2. Technology Stack

Core:
- Rust

Smart Contracts:
- WebAssembly
- Rustをfirst-class smart contract languageとする

Canonical WASM Execution:
- Rust製deterministic interpreter
- wasmi等を候補とする

Optional Optimized Execution:
- Wasmtime
- native/JIT/AOT
- platform-specific accelerators

ただしoptimized engineはcanonical semanticsを変更してはいけません。


# 3. Repository Structure

workspace/
  Cargo.toml

  crates/
    protocol-types/
    protocol-config/
    canonical-encoding/
    crypto/
    hashing/
    commitments/
    objects/
    abi/
    execution/
    chain-ir/
    system-modules/
    fees/
    bonds/
    validator-set/
    consensus/
    fast-path/
    governance/
    upgrades/
    migrations/
    zk/
    node-core/
    runtime/

  adapters/
    memory/
    native-http/
    cloudflare-workers/
    vercel/
    supabase/
    aws-lambda/
    deno/

  sdk/
    rust/
    typescript/

  contracts/
    system/
    examples/

  tests/
    integration/
    adversarial/
    upgrade/
    determinism/
    cryptography/
    zk/


# 4. Canonical Encoding

Hash functionの選択以上に、
「何をhash/signするか」のbyte representationを厳密に定義してください。

protocol-criticalな型についてcanonical serializationを定義する。

要件:

- deterministic
- injective
- versioned
- platform independent
- architecture independent
- map iteration orderに依存しない
- float禁止
- ambiguous concatenation禁止
- length framing必須
- enum discriminant明示
- integer endian明示

単純な

H(a || b || c)

は禁止。

canonical framingを使用する。

例:

[protocol magic]
[type/domain id]
[encoding version]
[field count]
[field id]
[field length]
[field bytes]
...


# 5. Cryptographic Agility

Hash algorithmを一種類へハードコードしない。

ただしtransaction senderやsmart contractが
consensus-critical hash algorithmを自由に選択できる設計にはしない。

原則:

"Hash algorithms are agile, but never negotiable per transaction."

protocol/epochごとにHashSuiteを固定する。


# 6. Self-Describing Digest

裸の32-byte hashをprotocol typeとして乱用しない。

例:

#[repr(u16)]
enum HashAlgorithmId {
    Sha2_256   = 0x0001,
    Sha3_256   = 0x0002,
    Blake3_256 = 0x0003,
}

struct Digest32 {
    algorithm: HashAlgorithmId,
    bytes: [u8; 32],
}

algorithm identifierはcanonical serializationに含める。

Digestは原則としてself-describingにする。


# 7. Hash Suite

用途ごとのhash algorithmをProtocolConfigで管理する。

struct HashSuite {
    id: HashSuiteId,

    transaction_hash: HashAlgorithmId,
    object_digest: HashAlgorithmId,
    effects_hash: HashAlgorithmId,
    code_hash: HashAlgorithmId,
    config_hash: HashAlgorithmId,
    certificate_hash: HashAlgorithmId,
}

Transaction自身がHashAlgorithmIdを自由指定してはいけない。

使用するHashSuiteは:

chain_id
protocol_version
epoch

から一意に決定する。


# 8. Genesis Hash Policy

Genesisでは保守性を優先する。

第一候補:

SHA-256

用途:

- TransactionHash
- ObjectDigest
- ExecutionEffectsHash
- CodeHash
- ProtocolConfigHash
- CertificateHash

SHA3-256も最初からimplementation supportしておき、
将来のalgorithm migration先として利用可能にする。

BLAKE3は高速hashとしてsupportしてよいが、
Genesis consensus root cryptographyとして必須にはしない。

重要:

HashAlgorithm implementationはinterfaceで抽象化する。


# 9. Hash API

例:

trait HashFunction {
    fn algorithm_id(&self) -> HashAlgorithmId;

    fn hash(
        &self,
        domain: HashDomain,
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        canonical_payload: &[u8],
    ) -> Digest32;
}

Hash関数呼び出し側が勝手なprefixを作らない。

domain separation framingはhashing crateで一元管理する。


# 10. Domain Separation

すべてのprotocol hashに明示的なdomain separationを適用する。

例:

enum HashDomain {
    Transaction,
    Object,
    ExecutionEffects,
    ContractCode,
    ProtocolConfig,
    Certificate,
    ValidatorSet,
    GovernanceAction,
    SystemModule,
    Migration,
    StateNode,
}

hash inputの概念形:

Hash(
    MAGIC
    || HashAlgorithmId
    || HashDomain
    || DomainVersion
    || ChainId
    || ProtocolVersion
    || PayloadLength
    || CanonicalPayload
)

ただし実際には単純concatではなくcanonical framingを使う。


# 11. Signature Domain Separation

署名対象も同様にdomain separationする。

署名domainには最低限:

- chain_id
- protocol_version
- epoch
- message_type
- signature_scheme_id

を含める。

cross-chain replay
cross-message replay
cross-version replay

を防ぐ。


# 12. Hash Suite Upgrade

HashSuiteはfuture epochで切り替え可能にする。

GovernanceAction:

ScheduleHashSuite {
    new_suite: HashSuiteId,
    activation_epoch: Epoch,
}

即時切替は禁止。

例:

Epoch 1:
HashSuiteV1 = SHA-256

Epoch 500:
HashSuiteV2 = SHA3-256

古いDigestはalgorithm IDを保持するため、
読み取り可能でなければならない。


# 13. No Global Rehash Migration

HashSuite変更時に全historical stateを一括rehashしてはいけない。

例:

Object@41
digest = SHA2_256:abc...

Epoch transition

Object@42
digest = SHA3_256:def...

古いObjectRefは旧algorithm identifier付きで有効。

更新されたversionから新HashSuiteを使える設計にする。

100TB stateでもhash migrationのために一括scanを要求してはいけない。


# 14. Adding Consensus-Critical Hash Algorithms

System Moduleとconsensus hash algorithmを区別する。

System Module内のcrypto primitive:
- governance transactionだけで追加可能

Consensus-critical hash algorithm:
- node implementationが対応済みであること
- protocol upgradeまたはsupported algorithm activationを経ること

未知のconsensus hash algorithmを
WASM moduleとして勝手に解釈してcore trust rootへ使用してはいけない。


# 15. Commitment Schemes are Separate from General Hashes

HashAlgorithmIdとCommitmentSchemeIdを分離する。

ZK/state commitmentはgeneral-purpose transaction hashingとは別問題として扱う。

例:

enum CommitmentSchemeId {
    SparseMerkleSha256V1,
    SparseMerklePoseidon2Bn254V1,
    SparseMerklePoseidon2Bls12381V1,
}

Poseidon2の場合は単に"Poseidon2"とだけ記録しない。

最低限以下をschemeとして固定する:

- finite field
- width
- rate/capacity
- round parameters
- constants version
- tree construction
- leaf encoding
- node encoding
- domain separation


# 16. State Model

EVM型global key-value storageは禁止。

Versioned Object Modelを採用する。

struct Object {
    id: ObjectId,
    version: u64,
    owner: Owner,
    type_hash: Digest32,
    schema_version: u32,
    data: Vec<u8>,
}

enum Owner {
    Address(Address),
    Shared,
    Immutable,
    System,
}

struct ObjectRef {
    id: ObjectId,
    version: u64,
    digest: Digest32,
}

Object data:

(ObjectId, Version)
    -> immutable blob

Object head:

ObjectId
    -> latest version / latest digest

Object lock:

(ObjectId, Version)
    -> TxHash


# 17. Transactions Declare State Access

transactionはアクセスするObjectを事前宣言する。

enum AccessMode {
    Read,
    Write,
    Consume,
}

将来的に:

Create
Append
Commutative(Operation)

を追加可能にする。

例:

CommutativeAdd
AppendOnly
CRDT-like operation


# 18. ABI as Execution and Concurrency Protocol

ABIはfunction signatureだけではない。

以下を含むprotocol-level manifestとする。

- function types
- argument schema
- Object types
- Read / Write / Consume
- ownership rules
- capabilities
- execution limits
- system module usage
- expected access paths

Rust contract例:

#[entry]
pub fn transfer(
    token: Read<Token>,
    from: Write<Balance>,
    to: Write<Balance>,
    amount: u128,
)

↓

AccessManifest {
    token: Read,
    from: Write,
    to: Write,
}

contractはtransactionで宣言されていないObjectへアクセスできない。

違反時はexecution trap。


# 19. Fine-Grained Parallelism

将来的にはObject単位より細かいaccess pathも表現可能にする。

例:

Write(
    object = DEX,
    path = pool[ETH_USDC]
)

Tx1:
DEX.pool[ETH_USDC]

Tx2:
DEX.pool[BTC_USDC]

なら競合しない。

AccessKey:

(ObjectId, ObjectPath)

まで拡張可能にする。


# 20. Serverless Node Architecture

validator invocation:

Request/Event
    ↓
load only required persistent state
    ↓
NodeCore.handle_event()
    ↓
deterministic state transition
    ↓
atomic persistence / CAS
    ↓
signed response / outbound messages
    ↓
return
    ↓
process disappears

process memoryはprotocol stateではない。


# 21. Node Core API

pub async fn handle_event<R: Runtime>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
) -> Result<NodeOutput>;

enum NodeEvent {
    SubmitTransaction(Transaction),
    ReceiveVote(Vote),
    ReceiveCertificate(Certificate),
    ReceiveConsensusMessage(ConsensusMessage),
    ApplyGovernanceCertificate(GovernanceCertificate),
    ApplyProtocolUpgrade(ProtocolUpgradeCertificate),
    ApplyValidatorSetChange(ValidatorSetChangeCertificate),
    Tick(Tick),
}

struct NodeOutput {
    responses: Vec<NodeResponse>,
    outbound_messages: Vec<OutboundMessage>,
}

node-core内部で禁止:

spawn()
while(true)
background jobs
persistent sockets
global mutable state


# 22. Runtime Abstraction

trait StateStore
trait BlobStore
trait Signer
trait Transport
trait Clock
trait Scheduler

等に分割する。

StateStoreには最低限:

get
put
compare_and_swap
atomic conditional update

を用意する。


# 23. Untrusted Transport

validator間常時P2Pを要求しない。

messageを運ぶ主体は:

- client
- browser
- RPC provider
- relay
- validator
- keeper

誰でもよい。

relayは:

drop
duplicate
reorder
delay
replay
mutate

できる前提。

protocol safetyはcryptographic signatureとpersistent stateに依存する。


# 24. Fast Path

Owned / non-conflicting Object transactionはglobal consensus orderingなしで処理可能にする。

validator:

1. chain_id verify
2. protocol_version verify
3. epoch verify
4. sender signature verify
5. fee payment verify
6. ObjectRef verify
7. ABI / AccessManifest verify
8. conflict check
9. deterministic execution
10. Object version lock
11. execution effects hash
12. Vote署名
13. response

validator同士の直接通信を必須にしない。


# 25. Vote

struct Vote {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,

    validator: ValidatorId,

    tx_hash: Digest32,
    execution_effects_hash: Digest32,

    signature: Signature,
}


# 26. Certificate

struct FastCertificate {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,

    tx_hash: Digest32,
    execution_effects_hash: Digest32,

    votes: Vec<Vote>,
}

quorum certificate成立後にcommit。

certificate処理は完全idempotent。


# 27. Shared Object Consensus

Shared / conflicting ObjectのみBFT orderingへ送る。

trait ConsensusEngine {
    fn protocol_id(&self) -> ConsensusProtocolId;

    fn on_event(
        ...
    ) -> Result<ConsensusOutput>;
}

候補:

- HotStuff-derived event-driven BFT
- DAG-BFT
- Mysticeti-like architecture

daemonを前提にしない。


# 28. Timeout Model

timeoutはNodeEvent::Tickとして外部入力する。

Tick senderはuntrusted。

利用可能:

Cloudflare Cron
Vercel Cron
Supabase cron
AWS EventBridge
client
random keeper

protocol自身がepoch/view/deadlineを検証する。


# 29. Validator Security Model

Native token stakingを必須としない。

以下を分離:

Validator Identity
Validator Membership
Validator Voting Power
Validator Bond
Validator Economics


# 30. Genesis Validator Model

Genesis時点ではbond tokenが存在しない可能性がある。

したがってpermissioned validator setでchainを起動可能にする。

例:

V1
V2
V3
V4

AdmissionPolicy:
GenesisPermissioned

BondAssets:
empty

BondRequirement:
None


# 31. Bond Assets After Genesis

Stablecoin contractがdeployされた後、
governance transactionでbond assetとして登録可能にする。

例:

Deploy USDC contract

↓

GovernanceTx:
AddBondAsset {
    asset_id: USDC,
    min_bond: ...,
}

↓

ScheduleValidatorPolicy {
    activation_epoch: 100,
    policy: BondAndGovernance,
}


# 32. Bond != Voting Power

bond amountはvoting powerを増やさない。

例:

100,000 USDC bond
-> voting power 1

10,000,000 USDC bond
-> voting power 1

bondの目的:

- Sybil cost
- slashable collateral
- validator eligibility

wealth-based voting powerにはしない。


# 33. Validator Admission Policies

enum ValidatorAdmissionPolicy {
    GenesisPermissioned,
    GovernancePermissioned,
    BondAndGovernance,
    BondRequired,
}

想定transition:

GenesisPermissioned
    ↓
BondAndGovernance
    ↓
必要ならBondRequired


# 34. Bond Asset Config

struct BondAssetConfig {
    asset_id: AssetId,
    min_bond: Amount,
    enabled: bool,
    unbonding_epochs: u64,
    max_validator_exposure: Option<Amount>,
}


# 35. Bond Object

struct BondObject {
    validator_id: ValidatorId,
    asset_id: AssetId,
    amount: Amount,
    bonded_epoch: Epoch,
    unlock_epoch: Option<Epoch>,
}

bond:

Stablecoin Object
    ↓
BondObject

unbond:

request_unbond
    ↓
unbonding period
    ↓
withdraw

unbonding period中はslash可能。


# 36. Slashing

cryptographically provable misconductのみslash対象。

Slash:

- same Object versionへのconflicting vote
- consensus equivocation
- conflicting finalized statements
- cryptographically provable double-signing

原則Slashしない:

- offline
- slow response
- request timeout
- provider outage
- Cloudflare outage
- Vercel outage

liveness failureとByzantine evidenceを明確に分離する。


# 37. Stablecoin Transaction Fees

native gas tokenは必須にしない。

struct FeePayment {
    asset: AssetId,
    max_fee: Amount,
    fee_object: ObjectRef,
}

approved stablecoin等で直接fee payment可能。


# 38. Fee Asset Registry

GovernanceAction:

AddFeeAsset
DisableFeeAsset
UpdateFeeAssetParameters

を実装。

canonical AssetIdを使用し、
symbol stringをidentityとして使わない。


# 39. Deterministic Fee Calculation

float禁止。

内部canonical unitを使用。

例:

1 USD = 1_000_000 fee units

Fee:

base_fee
+ execution_units * execution_price
+ state_read_units * read_price
+ state_write_units * write_price
+ storage_units * storage_price
+ system_module_units


# 40. Validator Fee Revenue

inflation rewardをprotocol前提にしない。

transaction fee:

Transaction Fee
    ↓
Certificate Signers
    ↓
stablecoin distribution

certificate signer setからdeterministically計算。


# 41. Fee Settlement Separation

Phase A:
TransactionExecutionEffects

Phase B:
Certificate

Phase C:
FeeSettlementEffects

最終signer set確定後にfee distributionを計算する。

rounding remainderのrecipientもcanonicalに決定する。


# 42. WASM Smart Contracts

禁止:

network
filesystem
wall clock
OS randomness
arbitrary external I/O
arbitrary global state lookup

許可:

declared object read
declared object write
object create
object consume
event emit
crypto functions
system module calls
deterministic protocol context


# 43. Execution Engine

trait ExecutionEngine {
    fn execute(
        &self,
        protocol_version: ProtocolVersion,
        module: &[u8],
        entrypoint: &str,
        inputs: &[ResolvedObject],
        args: &[u8],
    ) -> Result<ExecutionEffects>;
}

Canonical:
deterministic WASM interpreter

Optional:
native/JIT/AOT

output equivalence必須。


# 44. Chain IR

WASMを最終protocol semanticsへ固定しすぎず、
versioned deterministic Chain IRを導入できる設計にする。

Rust
 ↓
WASM
 ↓
Chain IR
 ↓
Execution

IR例:

LOAD_OBJECT
READ_FIELD
WRITE_FIELD
ADD_U64
CALL_SYSTEM
CREATE_OBJECT
CONSUME_OBJECT
EMIT_EVENT

Chain IR:

- deterministic
- versioned
- bounded
- statically inspectable
- ZK-friendly


# 45. ZK Architecture

                Chain IR
                   ↓
       ┌───────────┼───────────┐
       ↓           ↓           ↓
 Interpreter   Native/JIT    ZK Prover

初期は:

canonical interpreter
    ↓
RISC-V zkVM

等のbackendを許容。

将来的にChain IR専用proverへ変更可能。


# 46. Execution Proof

struct ExecutionProof {
    proof_system: ProofSystemId,

    tx_hash: Digest32,

    input_commitment: Commitment,

    output_commitment: Commitment,

    proof_bytes: Vec<u8>,
}

初期:
validator quorum

将来:
validator quorum + execution proof

さらに将来:
proof verification中心のvalidator execution

を可能にする。


# 47. ZK-Friendly State Commitment

transaction access setが事前確定していることを利用する。

StateRoot

├ proof A@12
├ proof B@44
└ proof C@8

      ↓

execution

      ↓

A@13
B@45
C@9

      ↓

NewStateRoot

state commitment schemeはCommitmentSchemeIdで明示する。


# 48. Dynamic System Modules

precompile追加のためにnode binary updateを必須にしない。

"precompile"をSystem Moduleへ一般化する。

Governance Transaction
    ↓
SystemModuleRegistry
    ↓
activation
    ↓
contractから利用


# 49. System Module

struct SystemModule {
    module_id: ModuleId,
    version: u64,

    canonical_code_hash: Digest32,
    semantics_hash: Digest32,
    manifest_hash: Digest32,

    activation_epoch: Epoch,
    status: ModuleStatus,
}

canonical implementationはportable deterministic codeを使用する。


# 50. System Module Manifest

struct SystemModuleManifest {
    module_id: ModuleId,

    input_schema: TypeSchema,
    output_schema: TypeSchema,

    max_input_size: u64,

    gas_model: GasModel,

    zk_hint: Option<ZkHint>,
}


# 51. Governance-Installed Crypto Modules

protocol upgradeなしでGovernance Transactionにより追加可能:

- Poseidon2
- SHA variants
- secp256k1 utilities
- Ed25519 utilities
- BLS utilities
- Groth16 verifier
- Plonk verifier
- future crypto primitives

ただしこれらはSystem Module level。

TxHash等のconsensus root primitiveとは明確に分ける。


# 52. Native System Module Acceleration

native optimized implementationはoptional。

CanonicalSystemModule(input)
==
NativeImplementation(input)

であること。

native implementation非対応validatorでも参加可能にする。


# 53. ZK System Module Acceleration

System Moduleにはzk_hintを設定可能。

例:

CALL_SYSTEM POSEIDON2

をZK backendで専用gadgetへ置換可能にする。

canonical semanticsとのequivalenceを保証する。


# 54. Protocol Versioning

type ProtocolVersion = u64;

protocol-critical messageには必ず:

chain_id
protocol_version
epoch

を含める。

unknown protocol version:
reject

silent fallback:
禁止


# 55. ProtocolConfig

struct ProtocolConfig {
    protocol_version: ProtocolVersion,

    hash_suite: HashSuiteId,

    commitment_scheme: CommitmentSchemeId,

    execution_rules: ExecutionRules,

    gas_schedule: GasSchedule,

    fee_assets: FeeAssetConfig,

    bond_assets: BondAssetConfig,

    validator_policy: ValidatorPolicy,

    consensus_parameters: ConsensusParameters,

    object_rules: ObjectRules,

    feature_flags: FeatureFlags,
}

ProtocolConfig自身もcanonical encodingしてhashする。


# 56. Protocol Upgrade

struct ProtocolUpgrade {
    from_version: ProtocolVersion,
    to_version: ProtocolVersion,

    activation_epoch: Epoch,

    new_config_hash: Digest32,

    migration_hash: Option<Digest32>,

    compatibility_policy: CompatibilityPolicy,
}

future epoch activationのみ。


# 57. Governance

trait GovernanceEngine {
    fn verify_action(
        action: &GovernanceAction,
        certificate: &GovernanceCertificate,
    ) -> Result<()>;
}

GovernanceAction例:

RegisterSystemModule
ActivateSystemModule
DeactivateSystemModule

AddFeeAsset
DisableFeeAsset

AddBondAsset
DisableBondAsset

ChangeValidatorAdmissionPolicy

AddValidator
RemoveValidator
ScheduleValidatorSet

ScheduleHashSuite
ScheduleCommitmentScheme

ScheduleProtocolUpgrade


# 58. State Migration

全state一括migration禁止。

Objectにschema_versionを持たせる。

lazy migration:

Old Object
    ↓
deterministic migration function
    ↓
New Object

migration functionもhash/versionで識別する。


# 59. Genesis to Bonded Network Transition

以下をprotocol-native lifecycleとして実装する。

Genesis
    ↓

permissioned validator set
bond assets = empty

    ↓

chain starts

    ↓

stablecoin contract deployed

    ↓

Governance:
AddFeeAsset(USDC)

    ↓

Governance:
AddBondAsset(USDC)

    ↓

Governance:
ScheduleValidatorPolicy(
    BondAndGovernance,
    activation_epoch = N
)

    ↓

grace period

    ↓

validators bond USDC

    ↓

Epoch N

BondAndGovernance activated


# 60. Runtime Adapters

Cloudflare:
- Workers
- Durable Objects / D1 abstraction
- R2

Vercel:
- Functions
- Postgres-compatible StateStore
- Blob/S3-compatible storage

Supabase:
- Edge Functions
- Postgres
- Storage

AWS:
- Lambda
- DynamoDB/Postgres
- S3

Deno:
- Edge/serverless adapter

Cloudflare-specific semanticsをprotocol safety requirementにしない。


# 61. Security Invariants

Invariant 1:
honest validatorは同一Object versionのconflicting transactionsへ二重voteしない。

Invariant 2:
quorum certificateなしにcommitted stateを変更できない。

Invariant 3:
同じcertificateから全validatorが同じstate transitionを導出する。

Invariant 4:
relayをtrustしない。

Invariant 5:
schedulerをtrustしない。

Invariant 6:
cloud providerをtrustしない。

Invariant 7:
process memoryをprotocol stateにしない。

Invariant 8:
protocol version mismatchはreject。

Invariant 9:
fee calculationはdeterministic。

Invariant 10:
fee settlementはdeterministic。

Invariant 11:
bond amountはvoting powerを増やさない。

Invariant 12:
slashにはcryptographic evidenceが必要。

Invariant 13:
native optimizationはcanonical semanticsを変更できない。

Invariant 14:
same transaction + same inputs + same protocol config
から全runtimeで同じeffects hashを生成する。

Invariant 15:
HashSuiteはtransaction senderがnegotiationできない。

Invariant 16:
hash domain間でcross-protocol collision semanticsを共有しない。

Invariant 17:
HashSuite変更時もhistorical digestを検証可能。

Invariant 18:
unknown hash algorithmをsilent fallbackしない。

Invariant 19:
general-purpose hashとZK commitment schemeを混同しない。

Invariant 20:
normal executionとZK executionが同じstate transition semanticsを持つ。


# 62. Required Cryptographic Tests

必須:

1. canonical encoding test vectors
2. HashDomain test vectors
3. SHA-256 hash vectors
4. SHA3-256 hash vectors
5. Digest algorithm ID serialization vectors
6. cross-domain hashが異なること
7. cross-chain hashが異なること
8. cross-protocol-version hashが異なること
9. equivalent structured payloadが同一canonical bytesになること
10. ambiguous structured payloadが同一bytesにならないこと
11. old HashSuite digest verification
12. HashSuite epoch transition
13. unknown HashAlgorithmId rejection
14. unknown CommitmentSchemeId rejection
15. no silent fallback


# 63. Required Integration Tests

Test 1:
4 validators
f=1
quorum=3

Alice -> Bob transaction

certificate成立後、
全validatorで同じdigest。


Test 2:
same Object version conflict
double vote禁止。


Test 3:
independent Objects
parallel execution可能。


Test 4:
certificate replay/idempotency。


Test 5:
requestごとにNode process完全破棄。


Test 6:
relay reorder/duplicate/delay/stale。


Test 7:
stablecoin transaction fee。


Test 8:
vote arrival orderが異なってもfee settlement一致。


Test 9:
Genesis permissioned modeでbond無しにchain起動。


Test 10:
stablecoin deployment後AddBondAsset。


Test 11:
BondAndGovernance future activation。


Test 12:
validator stablecoin bond。


Test 13:
bond額によらずequal voting power。


Test 14:
equivocation slash。


Test 15:
offlineのみではslashしない。


Test 16:
Protocol Version N -> N+1。


Test 17:
old epoch replay rejection。


Test 18:
lazy migration。


Test 19:
GovernanceのみでSystem Module追加。


Test 20:
node binary updateなしでportable System Module実行。


Test 21:
native System Module equivalence。


Test 22:
ZK gadget equivalence。


Test 23:
normal execution / ZK execution effects hash一致。


Test 24:
Cloudflare/native adapterでeffects hash一致。


Test 25:
HashSuiteV1 SHA-256でObject作成。


Test 26:
future epochでHashSuiteV2へ移行。


Test 27:
旧SHA-256 ObjectRefを新epochで正しくread。


Test 28:
Object更新後は新HashSuite digestを使用。


Test 29:
global state rehash無しにmigration可能。


Test 30:
HashAlgorithmId/domain/versionを変更するとhashが必ず変化。


# 64. Coding Requirements

production-quality Rust。

必須:

- unsafe原則禁止
- library codeのunwrap乱用禁止
- typed errors
- thiserror等
- structured logging
- metrics abstraction
- deterministic serialization
- canonical cryptographic framing
- no global mutable state
- no background tasks in node-core
- no vendor dependency in protocol core
- domain-separated hashes
- domain-separated signatures
- explicit chain_id
- explicit epoch
- explicit protocol_version
- explicit HashAlgorithmId
- explicit CommitmentSchemeId
- serialization test vectors
- cryptographic test vectors
- property-based testing
- fuzz testing
- adversarial tests
- cross-runtime determinism tests
- public API doc comments


# 65. Implementation Order

## As-Is milestones and To-Be destination

このPhase一覧はincremental deliveryの順序であり、最終品質の定義ではない。
`implemented`はそのPhaseのAs-Is milestoneが実装・検証されたことだけを意味し、
production-ready、mainnet-ready、監査済みを意味しない。

この文書のTo-Beは一貫してproduction-grade L1である。したがって:

- experimental、temporary、mock、reserved、deferred、interface-onlyな実装を
  production上の完成形として扱ってはいけない。
- 各experimental milestoneにはproduction exit criteriaを残し、criteriaを満たすまで
  TODOから削除したり「完了」と解釈したりしてはいけない。
- 後続PhaseはAs-Isの制約から逆算してTo-Beとの差分を閉じる。実験実装を別名で
  複製するだけのPRを新しいPhaseの完了としてはいけない。
- mainnet release判断はPhase番号ではなく、cross-phase production release gateと
  security reviewの充足で行う。
- READMEのcurrent statusとARCHITECTUREのimplemented behaviorはAs-Isを記録し、
  TODOはTo-Beと未解決のproduction gapを保持する。
- 各PhaseのPRを完了するときは、TODOのAs-Isと残存production exit criteriaを同時に
  更新する。criteriaを満たしていない項目へ単に`implemented`だけを付けない。

Phase 1:
- workspace
- protocol primitives
- canonical encoding
- HashAlgorithmId
- Digest types
- HashDomain
- HashSuite
- SHA-256 implementation
- SHA3-256 implementation
- crypto/signatures
- cryptographic test vectors

Phase 2:
- Object model
- ObjectRef
- access modes
- ABI

Phase 3:
- Runtime abstraction
- MemoryRuntime
- persistence layout

Phase 4:
- Validator identity
- Genesis validator set
- Epoch model

Phase 5:
- Fast Path
- Object locks
- Vote
- Certificate

Phase 6:
- Fee asset registry
- stablecoin fees
- validator fee distribution

Phase 7:
- Bond assets
- BondObject
- slashing evidence
- validator admission

Phase 8:
- Governance
- GenesisPermissioned -> BondAndGovernance

Phase 9:
- deterministic WASM ExecutionEngine
- Rust contract SDK

Phase 10:
- Chain IR

Phase 11:
- System Module Registry
- governance-installed precompiles
- native acceleration

Phase 12:
- Protocol upgrades
- HashSuite upgrades
- FeatureFlags
- lazy migrations

Phase 13:
- Shared Object consensus

Phase 14:
- CommitmentScheme abstraction (implemented)
- Poseidon2-based experimental ZK commitment suite (BN254 implemented;
  BLS12-381 identifier remains reserved and unsupported)
- execution proof interfaces (implemented; concrete proof backends deferred)

Phase 14 As-Is:

- SHA-256とexperimental Poseidon2/BN254のleaf/node commitment framingがある。
- Poseidon2/BN254はsafe Rustの監査容易性を優先した実装で、inactiveであり、
  temporary 4 KiB leaf limitがある。
- BLS12-381はidentifierのみ予約され、実装・activationされていない。
- ExecutionProofはcanonical envelopeとexact-ID verifier dispatchまでであり、
  concrete prover/verifier、verification key lifecycle、protocol activationはない。

Phase 14 To-Be production exit criteria:

1. Commitment scheme specificationを独立したprotocol specificationとして固定する。
   field modulus、S-box、width/rate/capacity、round constants、byte-to-field mapping、
   padding、endianness、tree depth、key-bit order、empty nodes、leaf/node domains、
   proof encodingを曖昧さなく記述する。
2. Poseidon2 implementationは独立レビュー済みの実装へ置換するか、現実装を
   production cryptographyとして別実装とのcross-check、property/fuzz test、
   side-channel評価、性能評価、暗号レビューまで完了させる。単一KATだけでは
   production承認としない。
3. temporary 4 KiB limitを、object size・proof cost・validator CPU budgetから導いた
   protocol上の正式な上限へ置き換える。上限内のworst-case benchmarkとDoS budgetを
   nativeおよび対象edge runtimeで満たす。
4. 完全なversioned sparse-Merkle treeを実装する。empty root、membership/non-membership
   proof、更新proof、複数objectのcanonical ordering、batch update、old/new root検証、
   malformed proof rejection、stable vectorsを含める。
5. CommitmentScheme activation/migrationをProtocolConfigとgovernance-controlled scheduleへ
   統合する。validator capability、future activation、unknown/unsupported scheme rejection、
   historical root/proof verification、rollback非依存のlazy migrationを検証する。
6. BLS12-381 identifierはproduction parameter setと実装を完成させるか、未対応のまま
   予約する理由とactivation禁止を明文化する。identifierの存在だけをsupportと数えない。
7. ProofSystemIdはproof system名だけでなく、version、curve/field、transcript、proof format、
   public statement version、verifying-key commitment、program image/circuit commitmentを
   一意に固定するregistry/specificationへ接続する。
8. 少なくとも1つのconcrete prover/verifier backendを実装し、Chain IR canonical executionと
   proven executionのeffects/output commitment一致、invalid proof rejection、resource bounds、
   deterministic cross-runtime verification、stable vectorsを検証する。
9. validator quorum onlyからquorum + proof、さらにproof-centric verificationへ移る
   activation policy、failure policy、fee/gas accounting、observability、
   consensus rollbackに依存しないsafe disable/recovery planを実装する。
10. cryptographic review、adversarial test、fuzzing、cross-implementation vectors、
    reproducible benchmark、independent security auditを完了する。これらを満たすまで
    Poseidon2とexecution proofをproduction-readyまたはmainnet-readyと表現しない。

Phase 15:
- native HTTP adapter (implemented As-Is)

Phase 15 prerequisites:

- bounded canonical frame decoder (implemented)
- deterministic node-core event boundary with one-key CAS persistence
  (implemented As-Is)
- adapter-neutral canonical request/response contract (implemented As-Is)
- bounded versioned multi-key StateStore transaction contract with an in-memory
  atomic reference implementation (implemented As-Is)
- declared-access transactional node-core invocation over versioned snapshots
  and atomic write sets (implemented As-Is)
- canonical request-id/event-digest dedup record and request-scoped outbox batch
  in the same atomic commit (implemented As-Is)
- ordered one-message outbox claim/lease/ack cursor with explicit at-least-once
  redelivery semantics (implemented As-Is)
- native HTTP default path using atomic deduplication and request-scoped
  persisted outbox lease/send/ack delivery (implemented As-Is)
- local durable SQLite TransactionalStateStore with WAL, synchronous FULL,
  BEGIN IMMEDIATE, revision tombstones, and schema identity checks (implemented As-Is)
- production persistence architecture separating validator-local atomicity
  domains, normalized logical data, indexed outbox recovery, provider mappings,
  migration, retention, and disaster recovery from the SQLite reference
  (design accepted; implementation pending)
- complete declared read-set revision assertion in transactional and
  idempotent node-core commits, including read-only and absent keys
  (implemented As-Is; domain-aware node-core migration pending)
- non-zero AtomicityDomainId、dedicated bounded/canonical read assertion set、
  put/delete mutation set、mutation-read containment、64 MiB aggregate envelope、
  domain-isolated memory conformanceを持つDomainTransactionalStateStore
  (implemented As-Is; node-core/durable provider migration pending)

Phase 15 As-Is scope:

- NodeEventはchain_id、protocol_version、epoch、non-zero request_id、closed event kind、
  bounded canonical payloadを持つ。
- node-coreはcontextをstate read前に検証し、1 event / 1 explicit state valueをpureな
  NodeStateMachineへ渡す。
- transition outputはcompare-and-swap成功まで返さない。競合時は内部retryせず、
  adapterへStateConflictを返す。
- node-core自身はsign、send、schedule、spawn、background loopを行わない。
- request_idはdeduplicationを実装するためのidentityであり、存在だけではidempotencyを
  保証しない。
- 現在のsingle-key CASはnative adapter統合用の実験的境界であり、production persistence
  architectureの完成形ではない。
- runtimeにはuniqueかつkey順へcanonicalizeされたbounded write-set、monotonic per-key
  revision、delete tombstoneによるABA防止、全revision一致時だけall-or-noneでcommitする
  TransactionalStateStoreを追加した。MemoryStateStoreはatomicity/conflict/bounds検証用の
  As-Is referenceでありdurable実装ではない。
- runtime-sqliteはexact-pinned bundled SQLiteを使い、WAL + synchronous FULL、5秒busy timeout、
  BEGIN IMMEDIATE、8-byte revision、delete tombstone、application/schema ID fail-closedを実装する。
  reopen persistence、ordered conflict、revision overflow、CASを検証する。recovery adapter向けには
  StateStore point-readと分離したStateKeyScannerを実装し、non-empty binary prefix、prefix内exclusive
  cursor、1,024以下のnon-zero limit、canonical order、1-row lookahead continuation、tombstone visibilityを
  強制する（implemented As-Is）。page間snapshotではないため各sweepをprefix先頭から再開する必要がある。
  blocking local-disk storeでありproduction-grade componentsを使うdeployment compositionは未実装である。network filesystem、
  kill -9/power-loss、backup/restore、capacity検証なしにprovider production persistence完成とはみなさない。
- `PERSISTENCE.md`はSQLiteをlocal durable reference/conformance fixtureに限定し、production To-Beを
  `(chain_id, validator_id, atomicity_domain)`単位のsingle-writer authority、全read-set revision assertion、
  normalized object/request/outbox/checkpoint/migration schema、indexed due-outbox claim、writer fencing、
  content-addressed blob、明示的migration/backup/restoreとして固定する。PostgreSQLを最初の
  production-oriented reference targetとし、Cloudflareは1 domain = 1 SQLite-backed Durable Object、
  AWSは初期single fenced writer regionへ写像する（design accepted; implementation/certification pending）。
  D1 read replica、DynamoDB Global Tables、scheduler/queue/alarmをauthoritative atomicityやconsensus trust rootに
  してはならない。cross-domain writeは別protocol decisionなしにbest-effort dual writeで実装しない。
- atomicity domain IDはprovider/database addressではなくgenesisまたはgovernance activationでcommitされる
  logical protocol identityとする。初期DomainPlacementManifestはmonotonic rule version、exactly one non-zero
  never-reused domain、closed `AllState` rule、activation epochを持つ。node-coreはbounded access plan確定後かつ
  state read前に全application keyをresolveし、receipt/outbox/deliveryはそのinvocation domainを継承する。
  `(chain, validator, logical domain)`からPostgreSQL/DO/AWS authorityへのbindingはwriter-fenced deployment
  metadataでありprotocol identityへ混ぜない。AtomicityDomainIdはprotocol-typesへ置き、zeroをrejectする。
  DomainPlacementManifestはnon-zero rule version、domain、closed AllState tag、activation epochをcanonicalizeし、
  historical ProtocolConfig encoding v1を維持したままprotocol version 2+のfield 14/encoding v2としてcommitする。
  v1+manifest、v2+-manifest、empty access、pre-activation resolveはfail closedする（implemented As-Is;
  node-coreはevent context検証後にaccess planを1回だけderiveし、storage read前にmanifestをresolveして、
  committed outputと同じdomainを返すadditive handlerを持つ。native-httpはDomainTransactionalStateStore限定の
  additive routerでそのdomainをrequest-scoped outbox claim/ackまで引き回し、HTTPからdomainを受け取らない
  （implemented As-Is; durable domain store/indexed unattended recovery pending）。
- runtimeはnon-zero 32-byte AtomicityDomainId、unique/canonicalなAtomicStateReadSetと
  AtomicStateMutationSet、それらを1 domainへ閉じ込めるAtomicStateTransactionを持つ。
  全mutation keyはread assertionを必須とし、各set 4,096 keysおよびaggregate represented bytes 64 MiBを
  shared safety ceilingとして検証する。MemoryStateStoreは同一keyのdomain isolation、complete-read conflict時の
  all-or-noneを検証する（implemented As-Is）。legacy unscoped stateはprivate test domainへ隔離され、
  node-coreはadditiveなdomain-aware transactional/idempotent handlerでapplication state、dedup receipt、
  outbox batch、initial delivery cursorを1 domain transactionへ接続した（implemented As-Is）。同一keyの
  domain isolation、replay、dependency conflict時にresult/receipt/outboxを一切publishしないことを検証する。
  outbox lease/ackにもdomain-aware entrypointを追加し、legacy/domainでidentity、lease、cursor検証を共有しつつ、
  immutable batch assertionとdelivery mutationを1 domain transactionへ閉じ込めた（implemented As-Is）。
  resolved-domain native request compositionは接続済みだが、runtime-sqlite、legacy default router、scan-based
  unattended recovery、provider adapterはまだnew contractへ移行していない。
- production durable operation boundaryはnon-zero monotonic writer fence、absolute storage deadline、
  bounded non-zero correlation IDを1 invocation contextとして分離し、commit outcomeをCommitted、
  definite Rejected、Indeterminateへ閉じた。revision conflict、stale fence、serialization abort、
  commit dispatch前に証明されたdeadline/unavailabilityだけをdefinite abortとし、dispatch後のdeadline、
  connection loss、cancellationはbackendのauthoritative abort evidenceなしに失敗扱いしない
  （boundary/node-core/native composition/normalized PostgreSQL implemented As-Is;
  other durable provider wiring pending）。correlation ID、fence、deadlineを
  protocol canonical input、request dedup identity、HTTP caller-selected authorityにしてはならない。
- runtimeはnormalized store向け`DurableInvocationTransaction`を持つ。logical domain、read-onlyも許すoptional
  complete state section、typed canonical receipt、optional typed ordered outbox、explicit object sectionを分離し、
  aggregate bytesとstate domain、receipt/outbox request ID、event digest一致をI/O前に検証する。
  object sectionはcanonical unique/sortedなbody-free head assertion、read containment付きcreate/update/delete、
  distinct immutable versionとABA-safe head revision、inline canonical `objects::Object`またはself-describing blob参照を持つ。
  inline owner projectionはwrite時にtyped `Owner`から導出し、immutable versionはheadと別APIで読む。head readは
  inline bytesをSELECTせず、immutable row metadataとinline presence/lengthのみを検証する。headのowner/routing projectionは
  routing hintでありauthorizationではない。executionは別途exact versionを読み、head version/digestとの一致、inline Object decode、
  typed owner一致を検証しなければならず、blob-backed executionはfetch/content verification実装までfail closedとする。
  memoryとPostgreSQLはstate/object/receipt/outboxを同一atomic boundaryで実装済みである。authenticated
  structured durable pathはsigned read-only manifestをexact head/immutable inline versionからloadし、verified
  senderに対するtyped owner authorizationと完全なhead assertionを同一commitへ接続した（implemented As-Is）。
  すべてのimmutable object versionはcreating chain/protocol version provenance
  （`DurableObjectProvenance`、DR-0068、required field、schema redefinition済みなので
  legacy行は存在しない）を保持し、node-coreは`load_and_authorize_objects`内で
  inline payload/identity/schemaのcross-checkの後・owner-projection cross-checkの前に、
  stored `Digest32`のself-describing algorithmとそのprovenanceを使い
  `hashing::verify_digest`でdigestを独立に再計算・検証する
  （reader epochのhash suite resolverは使わない。使うとlegitimateなhistorical objectを
  誤ってrejectしてしまう）。record provenanceのchain_idはtrusted event chainと
  一致しなければならないが、protocol_versionには同等のcheckはない
  （olderなobjectも引き続きverifyできなければならないため）。inline bodyは
  hashing前に`MAX_AUTHENTICATED_OBJECT_BODY_BYTES`（1MiB/object）と
  `MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES`（8MiB/invocation）でbound済みである
  （pre-activation admission budgetであり測定済みcapacity limitではない）。
  PostgreSQLはgeneration oneをschema identity v2へin-place redefinitionし
  （bootstrap-only、`POSTGRES_SCHEMA_GENERATION`は1のまま）、`object_versions`に
  `created_chain_id_bytes`/`created_protocol_version`と
  `CHECK (created_chain_id_bytes = chain_id_bytes)`を追加した。既存のv1 schemaは
  bootstrap/inspection/request-path metadata readのすべてでfail closed
  （`SchemaMismatch`）する（object digest provenance/recomputation implemented As-Is;
  DR-0067の該当pending itemを解消した）。
  Write/Consume、Shared/System owner、blob body、module load、object effects、fee debit、owned fast pathは未実装である。
  node-core additive handlerはmanifest domainをI/O前にresolveし、typed receipt replayをstate readより先に行い、
  read-only assertionを含むstate/receipt/outboxをこのenvelopeへ構築する。definite commitまたはexact replay以外では
  outputを返さない。single-lock memoryとnormalized PostgreSQL conformance storeでatomic publication、object lifecycle/ABA、
  conflict rollback、read-only、bound domain、fence、deadline、object read-count bound、blob round-trip、replayを検証する
  （runtime/memory/PostgreSQLとnode-core authenticated read-only object authorization implemented As-Is;
  object effectsとprovider certification pending）。
- owned transaction fast pathの認証基盤として、`crypto`にexact-pinned
  `ed25519-zebra` 4.2.0（`[workspace.dependencies]`でdefault features無効を
  一箇所宣言。committed `Cargo.lock`はその依存`curve25519-dalek`を4.1.3で
  pinし、直接使わないunused dependencyとしては追加しない。Dependabotが
  どちらかのpinへ更新を提案してもauto-mergeせず既存policyでreview-gateする）
  によるZIP-215準拠のreal `Ed25519Verifier`を追加した（32-byte検証鍵・
  64-byte署名のみを受理し、非canonical encodingとsmall-order pointを
  受理するconsensus-deterministicな検証で、production signerは追加しない。
  `verify_framed`はlength検証済みの署名を明示的な`[u8; 64]`へcopyしてから
  infallibleなfixed-size `From`constructorで`Signature`を構築し、
  すでにlength検証済みの値に対するdead/mislabeledなlength-error mappingを
  持たない。`runtime::MemorySigner`はtest/local runtime合成用のpublicな
  in-memory wiring fixtureであり、意図的にnon-cryptographicで、protocol
  authenticationには絶対に使ってはならない。test-only compilation flagで
  gateされているわけではない）。`SignatureSigner::sign_canonical`と
  `SignatureVerifier::verify_canonical`（trait default method）は、
  caller供給の`SignatureDomain::signature_scheme_id`がsigner/verifier自身の
  `scheme_id()`と一致しない場合、framingや暗号操作を一切行う前に型付き
  `CryptoError::SignatureSchemeMismatch { expected, actual }`でrejectする
  （`frame_signature_message`自体のbyte formatは不変）。`protocol-config`には
  committed `TransactionAuthProfile`をProtocolConfig field 15・encoding v3
  として追加し、protocol version 3以降でのみ必須、v1/v2 historical bytesは
  不変である。profileのprofile idはarbitraryなnon-zero labelではなく
  committed protocol identifierであり、`TransactionAuthProfile::new`と
  新設の`TransactionAuthProfile::validate`（`new`および
  `ProtocolConfig::validate`から、zero idの再検証だけでなく呼ばれる）は
  同じrulesを適用する: zeroを`ZeroTransactionAuthProfileId`でreject、
  public定数`ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`（値1）以外の
  全てのidを型付き`UnsupportedTransactionAuthProfileId(u16)`でreject
  してからscheme/binding組み合わせを検証する。`ed25519_address_is_public_key()`
  は引数を取らず常にこの1つのprofileだけを構築する。`SignatureSchemeId`
  （Ed25519のみ実装、Secp256k1は予約でfail closed）、closed
  `AddressBinding`（実装済みは`AddressIsPublicKey`のみ）を持つ。
  `resolve_transaction_auth_profile`はcommitment/resolution層であり、
  返す前に`ProtocolConfig::validate()`を必ず呼ぶため不正な設定は
  activation判定より先にfail closedする。`protocol-config`は`crypto`にも
  `objects`にも依存せず、署名検証は一切行わない（`crypto`/`protocol-config`
  implemented As-Is; RFC 8032 known-answer、ZIP-215 small-order/non-canonical
  point acceptance、RFC 8032 §5.1.7とZIP-215が共に要求するS<lルールに基づく
  非canonical `S` rejection、signature scheme mismatch rejection、
  premature/missing profile・unsupported profile id・unsupported scheme・
  不正configのadversarial testを含み、`ed25519-zebra` 4.2.0 /
  `curve25519-dalek` 4.1.3で再確認済み）。strict transaction authentication
  とproduction-oriented structured durable native routeの接続もimplemented
  As-Is（下記bullet）。persistent sender nonceもimplemented As-Is（下記bullet）。
  ただしfee、module/object effects、FastCertificateは引き続き未実装であり、protocol
  version 3のlive activationは禁止する。
- `execution::decode_transaction`はexecution::Transaction v1の厳密な
  standalone canonical decoderを追加した：type id/encoding version 1を要求し、
  field 1-10と12を必須、field 11（`fee_payment`）のみoptionalとして
  exactに要求し、unknown/missing/duplicate/out-of-order field、trailing/
  truncated bytes、invalid UTF-8、誤ったnumeric/address/digest length、
  unknown tag/algorithmをtyped errorでrejectする。`AccessManifest`/
  `AccessEntry`（`abi`）、`ObjectRef`/`ObjectId`/`Address`/access mode
  （`objects`）、`FeePayment`/`AssetId`（`fees`）にも対応するpublic decoder
  を新設し、既存のstable type idとencoding version 1を再利用した。
  entrypoint・args・signature・manifest entry countには既存の32 MiB
  canonical frame boundより厳しいtransaction-specific boundをattacker-
  controlledなbytes/entriesをcopyする前に適用し、`AccessManifest`内の
  重複`ObjectId`とnon-canonicalなcount/field layoutをrejectし、最後に
  decode結果を再encodeしてinput bytesとbyte-for-byte一致することを要求する
  （代替表現を一切受理しない）。署名検証やSignatureDomain構築は一切行わない
  canonical-structure boundaryのみであり、上記の**hard activation
  constraint**を単独で満たすものではない：protocol version 3の活性化には、
  committed profileから`SignatureDomain`を構築し実際に署名を検証する
  authentication dispatch層が別途必要である。
- `node-core`はこのauthentication dispatch層をstandaloneなfail-closed
  boundary `node_core::transaction_auth`として追加した（`node-core`が
  workspace dependencyとして`execution`と`crypto`を新たに追加。
  `protocol-config`はこれまで通りどちらにも依存せず、署名検証も行わない）。
  公開entrypoint `authenticate_transaction_bytes(input, context)`は
  明示的な`TrustedTransactionContext`（caller供給の`ChainId`/`Epoch`と
  committed `ProtocolConfig`への参照。protocol version権限は
  `ProtocolConfig`のみが持ち、drift可能な別のcaller供給versionは受け付けない）
  を受け取り、(1) 委任profileをresolveし、premature/missing/invalidな
  configをdecode前にfail closedし、(2) `execution::decode_transaction`で
  厳密にdecodeし、(3) decode済みtransactionの`chain_id`/`protocol_version`/
  `epoch`をtrusted context/configと比較し、鍵や署名が不正な場合でも
  暗号処理より前に型付きmismatch errorでrejectし、(4) trusted contextと
  resolved profileのみから、正確なstable message family文字列
  `"transaction-v1"`を用いて`crypto::SignatureDomain`を構築し、
  (5) signature fieldを除いたsignable payloadをencodeし、明示的で
  deterministicな`node_core::MAX_TRANSACTION_SIGNABLE_BYTES` boundを
  `crypto::frame_signature_message`やverifierがallocate/hashする前に適用して
  oversizedなsignable bytesを型付きerrorでrejectし、(6) 委任profileの
  closed `AddressBinding`のうちimplemented済みの`AddressIsPublicKey`のみを
  実装し、transaction senderの正確な32 bytesをEd25519 verification keyとして
  使い（未実装のfuture binding/schemeはconfig/profile validationにより
  fail closedし、fallbackしない）、(7) committed
  `crypto::Ed25519Verifier`で検証し、malformed key/malformed signature
  lengthの型付き`CryptoError`と、well-formedだが暗号学的に不正な署名
  （型付き`InvalidTransactionSignature`）を区別し、(8) `Ok(true)`の場合のみ
  新設の`AuthenticatedTransaction`を返す。`AuthenticatedTransaction`は
  内部の`execution::Transaction`をprivate fieldとして持ち、read-only
  accessorとconsuming accessorのみを公開し、公開constructorを持たない。
  production signerは追加せず、devテストのみexact-pinned workspace
  `ed25519-zebra` `SigningKey`で決定的な署名を生成する。deterministic real
  Ed25519 happy path、wrong signatureの`InvalidTransactionSignature`、
  malformed signature length/malformed verification keyの型付き
  `CryptoError`維持、chain/protocol-version/epoch mismatchの暗号処理前
  rejection（鍵や署名が不正でも）、chain/protocol-version/epoch/message
  family across domain replayの失敗、premature/missing profile・invalid
  configのfail-closed、bound到達時のverifier work前rejectionを含む
  exact signable bound behavior、strict canonical bytesのみ受理し
  malformed/代替表現は`ExecutionError`経由で失敗すること、signature field
  自身をsignable payloadがcoverしないこと、signable fieldの変更が
  authenticationを無効化することをtestで検証済みである
  （`node-core`実装、workspace test As-Is）。production-oriented
  structured durable native routeはcommitted `ProtocolConfig`をcomposition
  authorityとして受け、outer `NodeEvent`のcontextを検証してからinner
  transactionを`AuthenticatedSubmitTransaction`へ変換する。認証はaccess
  plan、identity、storage用clock、storage read/write、transition、outbox
  claim/sendより前であり、wrapperは同じconfig由来のplacementを保持して
  normalized durable commitへ渡す。exact duplicateもreceipt照合より前に
  再認証する。generic node-core handlerおよびlegacy native routeは
  `SubmitTransaction`を型付きでrejectし、unauthenticated bypassを残さない。
  invalid signature、inner/outer chain/version/epoch mismatch、missing profile、
  trailing/non-canonical bytesはmachine/identity/clock/storage/sendのcall count
  zeroで失敗するtestを持つ。transaction wire field/encoding versionは追加して
  いない。protocol version 3のlive activationはfee/module/object effect/
  FastCertificateのatomic compositionが完成するまで禁止する。
  **Hard activation constraint:** `SubmitTransaction`以外の
  externally acceptedなnode-event family(特にcertificate、protocol upgrade、
  validator-set change)も、live activationの前に同等のauthenticated/authorized
  ingressを持たなければならない。generic node-core handlerが`SubmitTransaction`を
  rejectすることは、それらの他のfamilyをunauthenticatedで受理してよいことを意味
  しない。outer `NodeEvent`の`request_id`はunsignedのidempotency identityの
  ままであり、fresh request IDのreplay protectionは下記のsigned persistent
  nonceが担う。
- authenticated structured durable `SubmitTransaction` pathは、verified inner
  transactionからのみprivateな`(sender, epoch, nonce)` reservationを導出し、
  `PersistenceLayout`のchain/protocol-version/sender/epoch namespaceにcanonical
  next-nonce record type `0xE006`を保存する。record自身もsender/epochをbindし、
  key/value mismatchやcorrupt bytesはfail closedする。missingはexpected zero、
  exact equalityのみを受理し、checked incrementをapplication state/receipt/
  outboxと同じnormalized durable invocationに含める。exact receipt replayは
  nonce readより先にreconcileして二重消費しない。fresh requestはnonceを
  application stateより先に読み、stale/skipped nonceをtransition/commit前に
  型付き`SenderNonceMismatch`でrejectする。`u64::MAX`はwrapせず
  `SenderNonceOverflow`でrejectする。native HTTPはそれぞれ409
  `sender-nonce-mismatch`、422 `sender-nonce-overflow`へ分離してmappingする。
  absent/existing nonce raceはread revision assertionにより片方のみatomic commit
  できる。committed Accepted/Rejectedはnonceを消費し、authentication/
  transition/pre-commit failureは消費しない。application planは全event familyで
  nonce prefixをclaimできず、authenticated pathはatomic state write slotを1つ
  reserveする。domain placement countにnonceは含めない。client-side future nonce
  queue/pipeliningは実装せず、exact next nonceを直列送信する。epoch/protocol-
  version rolloverでnamespaceを分離し、古いepochを受理しないtrusted
  `NodeConfig.epoch`とsigned epochをreplay boundaryとする。`u64::MAX`到達senderは
  epoch rolloverまで送信不能。indeterminate commitはfresh request IDに変えず
  original request IDでreconcileする。generic normalized state tableを再利用し、
  tombstone revisionを持つabsenceはexpected zeroへresetせずpersistence invariant
  でfail closedする。DB schema generationとTransaction wire/schema versionは
  不変。epoch pruningのproduction policyはdeferredであり、fee debitとbounded
  retentionがない間はnew senderによるstate growthがeconomic meteringされない。
  このAs-Is routeをlive transaction ingressとして公開してはならない。
  fee/object/effect/FastCertificateおよび他event
  familyのauthenticated/authorized ingressが残るためlive activationは引き続き
  禁止する（runtime/node-core/native implemented As-Is）。
- request pathのcommit直後deliveryはdomain-wide `claim_due_outbox`を流用しない。同じdomainのolder due workを
  今回requestと誤認しないよう、trusted `(domain, request_id, now, lease, expiry)`を持つexact-request claimを使う。
  memory conformanceはolder due rowが存在しても指定requestだけをclaimし、cross-request/domain lease reuseを拒否する
  native structured request pathは同一operation contextでcommit後にexact requestを最大1 message claimし、
  Indeterminate claim/ackを同一identityで1回reconcileし、未解決claimをsendしない
  （contract/memory/native/PostgreSQL implemented As-Is; provider durable adapters pending）。
- indexed production outbox boundaryはtrusted runtime timeとbounded restart-safe leaseを受け、
  `(available_at, request_id)`のstable index順で最大1件だけclaimする。scheduler cursorやprefix scanを
  authorityにせず、同じlease IDの再claimはindeterminate claimのreconciliationとして同じworkを返し、
  別workへのlease reuseはfail closedする。ackは同じrequest/index/leaseの再試行をidempotent successとするため、
  normalized storeはleaseごとのrequest/index bindingとacknowledged statusをowning batchのretentionまで保持する。
  last acknowledged identityだけでは後続message進行後のdelayed retryを処理できない。claim/ackはどちらもdefinite pre-commit rejectionと
  Indeterminateを分離し、未reconcileのclaimをtransportしてはならない
  （contract implemented As-Is）。nativeはtrusted deployment compositionからlogical domain、writer fence、
  lease未満のbounded storage timeout、restart-safe lease/correlation identityを受けるone-shot indexed recoveryを持つ。
  claim/ackのIndeterminateは同じidentityで各1回だけreconcileし、unresolved claimはsendせず、scan cursorを返さず、
  HTTPとblocking admissionを共有する。single-lock memory repositoryはinitial delivery、stable due order、lease expiry、
  same-lease reconciliation、retained attempt history、later progress後のdelayed ackを検証する
  （native/memory/PostgreSQL implemented As-Is）。
  PostgreSQL以外のdurable adapter、transport-aware deadline/cancellation、real scheduler bindingは未実装である。
- runtimeのnon-default `durable-conformance` test supportは同じblack-box caseをmemoryとPostgreSQLで実行し、
  deadline exact boundaryのread/commit/claim/ack definite rejection、complete-read write skew、concurrent
  absent-key create、tombstone ABA、definite contention outcome、retained outbox lease、writer-fence handoffを
  検証する。PostgreSQL live testはさらにpool acquisition/metadata lock待ちdeadline、retry ceiling到達時の
  serialization rejectionとunsupported schema generationのread/commit/claim/ack fail-closedを検証する
  （implemented As-Is）。optional shared commit-loss capabilityはbounded test-only `NoTls` TCP proxyを介し、
  plain state commitへCOMMIT dispatch直前のconnection lossを1回注入してstate ground truthが存在しないことを
  証明し、別途structured invocation commit・outbox claim・acknowledgementの3箇所へbackend COMMIT acceptance
  直後のconnection lossを注入して、いずれもIndeterminate(ConnectionLost)として分類されつつ、invocation commitでは
  exact state/receipt ground truthとRequestAlreadyCommittedを証明する。same-lease claim replayや
  same-identity ack replay単独ではpersistedとuncommittedを区別できないため、claimでは別leaseでのclaim probe
  （元leaseがまだactiveであることをNoDueWorkで証明）、ackでは元leaseでのreclaim probe（LeaseIdReuseとして
  rejectされることを証明）を先に行った上でsame-identity reconciliationを証明し、最後にconnection pool
  recoveryを検証する（implemented As-Is；backendがCOMMITへ成功応答を返したことの証跡であり、abrupt
  process/power lossに対するcrash durabilityの証明ではなく、TLS-path connection lossは
  対象外）。別途、serializedなlive testがcommitted structured invocation（state、exact receipt、
  1 due outbox message）の直後にintervening SQLなしでdatabase-service containerへ
  `docker kill --signal=KILL`し、`docker start`と新規connectionでexact state/receipt、
  `RequestAlreadyCommitted` replay、その1 requestへのexact claim/ack 1回に続く`NoDueWork`、
  最終unfaulted commitを検証する
  （implemented As-Is; ARCHITECTURE.md DR-0069）。これはlive host上のlive page cacheでの
  database-process SIGKILLとWAL recoveryの証明であり、abrupt host/power loss、storage
  write-cache flush/torn-write/media/filesystem fault、disk full/WAL exhaustion、connection
  exhaustion、TLS-path connection loss、backup/restore、capacity/load/soak、real writer
  failover、provider certificationは未実装である。
  別のrequired live testはdigest-pinned disposable PostgreSQLでPGDATA/WALを未充填の
  512 MiB tmpfs、database default tablespaceを別の64 MiB tmpfsへ置き、後者だけを満杯にする。
  direct SQLSTATE `53100`、pre-commit `UnavailableBeforeCommit`、state/receipt/commit sequence
  非公開、space解放後のsame pool/store recoveryとexact replay/claim/ackを検証する
  （bounded data-tablespace ENOSPCのみimplemented As-Is; ARCHITECTURE.md DR-0070）。
  さらに別のrequired live testはdigest-pinned disposable PostgreSQLで`pg_wal`だけを`initdb --waldir`で
  別の64 MiB tmpfsへ切り離し、未充填の512 MiB tmpfs上のPGDATA/default tablespaceとは明確に区別した上で
  WAL側だけを満杯にする。direct incompressible writeはWAL segment境界を跨ぐと引き続きSQLSTATE `53100`を
  返すが、severityはDR-0070のplain `ERROR`ではなく`PANIC`であり、直後に同じconnectionがcloseする
  （PostgreSQLがwhole postmasterをterminateしてcrash-restartするため、その後のautomatic recoveryも
  WAL不足で同様に失敗しserverが二度落ちる）。同じmount上でin-place recoveryした後、WALを独立に再充填し、
  bounded incompressible state mutationを使ってadapter自身のstructured invocation commitにWALを枯渇させ、
  serverを再度crashさせる。観測されたpublic outcomeはdefinite pre-commit
  `Rejected(UnavailableBeforeCommit)`である。adapter APIはraw database errorを公開しないため、exact
  SQLSTATE/severityを主張するのはdirectな第一cycleだけである。connectionだけでなく
  server全体が落ちるため、containerのentrypointをsupervisor scriptで上書きしてcontainer自体はcrash後も
  生存させ、`docker start`/`docker kill`を使わずWAL解放後に`pg_ctl start`で同じtmpfs mount上へin-place
  restartする。二回のrestartそれぞれでstrictly advanceした`pg_postmaster_start_time()`によりgenuineな
  crash/recoveryを証明した上で、
  同じpool/storeでstate/receipt/commit sequence非公開とrecovery後のexact replay/claim/ackを検証する
  （bounded WAL-filesystem ENOSPCのみimplemented As-Is; ARCHITECTURE.md DR-0071）。literal `COMMIT`時の
  WAL/data ENOSPCは未検証であり、この境界についてENOSPC固有の分類は主張しない。real-device ENOSPCと
  他のfault/capacity certificationも未実装のままである。
  さらに別のrequired live testはdigest-pinned disposable PostgreSQLをtiny exact `max_connections`、
  zero `superuser_reserved_connections`、zero PostgreSQL 16+ `reserved_connections`（
  `pg_use_reserved_connections` role向けの別のindependent reserved pool）で起動し、どのroleにも
  capacity carve-outを与えない。autovacuumも無効化するが、これはoptional quiescenceに過ぎない
  ——autovacuum worker/launcherは自身のseparate budgetから割り当てられ、`max_connections`から
  carve-outされることはない。すでにopenなoperator connectionがnamespaceをbootstrapしたまま
  scenario全体で開き続ける。databaseを作成したshort-livedなadmin clientをdropした直後、operator
  connection自身のconnectionだけがactiveであることをboundedにpollして確認する
  ——`Client`のdropはasynchronousなteardownを要求するだけなので、このpollがなければadmin client
  のbackendがblocker接続の厳密なcount開始時にtransientにcapacityへ残ってしまう可能性がある。この
  pollがsafeなのは、この時点ではまだ`r2d2` poolが存在せず、このtestが開始した以外の何もconnection
  countを自発的に変化させ得ないためであり、この同じscenarioの後半（下記）でtransient countをpoll
  することがsafeでないのとは対照的である。小さくexactly boundedな数のdirect blocker
  connectionでserverの全connection slotを飽和させ、direct probeのSQLSTATE `53300`（`FATAL`
  severity）とexact active client-backend countでgenuineなexhaustionを証明する。capacityがまだ
  exhaustedのまま、zero physical connectionを保持すると証明したmax-size-oneのadapter poolで1回
  bounded structured invocation commitを実行する。`r2d2`のconnection-acquisition waitはbareな
  refusalでは早期returnしないため、このcrateがfailureをclassifyする時点でcaller自身のoperation
  deadlineも構造的にちょうど経過しており、pool exhaustionとdeadline exhaustionは同一のdefinite
  pre-commit `Rejected(DeadlineExceededBeforeCommit)`へcollapseする（connectionとtransactionが
  既にopenな状態でfaultが発生するDR-0070/DR-0071とは異なり、`UnavailableBeforeCommit`にはならない）。
  adapter poolはsaturated中に新規connectionを開けないため、state/receipt/outbox行とcommit
  sequenceの非公開はstoreではなくstill-openなoperator connectionを通じて証明する。rejected
  attempt自身の内部connection試行は`commit_invocation`が返った後も止まらず、`r2d2`が独立して
  短いbackoffで再試行し続けるため、blocker connectionを厳密に1つだけ解放して空いたslotはこの
  testが呼び出すどの呼び出しとも無関係にその背後のretryが任意のタイミングで奪う可能性がある。
  解放直後の一時的なcountをpollしてこの独立したretryとraceさせるのではなく、次の
  `commit_invocation`呼び出しがcapacity獲得後に必ず成功することを要求し、成功後にstill-openな
  operator connectionを通じてsteady-stateのactive client-backend countが厳密に`max_connections`
  であり、そのうちちょうど1つがadapter pool自身の`application_name`を持つことを証明することで、
  adapter pool自身が解放されたslotを奪ったことを確定的に証明する。同じinvocationのrecovery、
  exact replay/claim/ack、pool usabilityも同じpool/storeで証明できる（bounded
  connection-exhaustion evidenceのみimplemented As-Is; ARCHITECTURE.md DR-0072）。real-device
  resource exhaustion、load/soak capacity、provider-managed pooler（例: PgBouncer）下での
  connection-pool挙動、production certificationは未実装のままである。別のrequired live testは
  digest-pinnedなsourceとtargetの2つの独立したdisposable containerを起動し、sourceで1件の
  structured invocation（state、receipt、1 pending outbox message）をcommitした後、
  `pg_dump -d <db> --no-owner --no-privileges --inserts`でsnapshotを取得する。`--inserts`は
  `COPY ... FROM stdin`の埋め込みdata block（`psql`自身が実装するclient-side convention）を
  回避し、self-containedな`INSERT`文だけのSQLをadapter自身の`postgres::Client::batch_execute`で
  直接targetへ適用できるようにする。PostgreSQL 18の`pg_dump`が付与する`psql`専用の
  `\restrict`/`\unrestrict`行（SQLではなくwireへ送ればsyntax errorになる）は事前に除去する。
  copied namespaceのfenceを進める前にexact schema identityと、restored namespace metadata・
  state・receiptをadapterのread path経由でexact ground truthとして検証し、operator-only
  `advance_writer_fence`でrestored namespaceのwriter fenceを進め、stale pre-backup context
  （旧fence）が`Rejected(WriterFenced)`でfail closedし公開なしであることを証明し、新fenceの
  fresh contextがexact restored receipt/stateをreconcileし、identical invocationで
  `RequestAlreadyCommitted`を観測してからrestored pending outbox
  payloadをclaim/ackし、新規workをcommitできることを証明する。negative pairではrequiredな
  `storage_metadata`の`CREATE TABLE`途中でcutしたdumpがsingle simple-query batchとしてatomicに
  failしschema markerを残さないことと、fixtureの`state_records` insertだけを除いたvalid dumpが
  schema・namespace metadata・receiptをrestoreしながらmissing stateによってdeeper rehearsal
  verification gateを通過しないことを証明する（bounded database-snapshot restore rehearsal evidenceのみ
  implemented As-Is; ARCHITECTURE.md DR-0073）。これは1回の`pg_dump`/SQL-execute snapshot
  cycleのrehearsalに過ぎずproduction backup/restore機能ではない。point-in-time recovery、
  continuous WAL archiving、concurrent write負荷下でのhot backup、
  `pg_basebackup`/replicationベースのbackup、backup encryption/off-host storage、
  checkpoint publication（`sunrise_edge.checkpoints`は未使用）、blob-manifest/state-root/
  encryption-key verification、production certificationは未実装のままである。
- ComposedRuntimeはStateStore、BlobStore、Signer、Transport、Clock、Schedulerをhidden defaultなしで
  明示的に所有・合成する。SQLiteへstate/dedup/outboxをcommit後にruntimeをdropし、同じDBを別compositionで
  reopenしてstateを再適用せずoutboxを送ること、send failure leaseがreopen後もexpiry前は抑止されexpiry時だけ
  attempts=2で再送されることを検証する（implemented As-Is）。これはorderly close/reopen conformanceであり、
  kill -9、torn write、filesystem failure、power lossの証明ではない。
- node-coreのtransactional pathはcontext検証後かつstate read前にevent-specific access planを
  確定し、全keyをrevision付きsnapshotとしてpure transitionへ渡す。undeclared/read-only updateを
  rejectし、更新しないread-write/read-only/absent/tombstoneを含む全観測revisionを
  `StateMutation::Assert`としてwrite-setへbindし、全commit成功までoutputを返さない
  （complete read-set assertion implemented As-Is）。
  native HTTP adapterはこのrecoverable transactional pathをdefaultにした。edge adapterの
  downstream service実装とdurable provider storeは別途必要である。
- recoverable transactional pathはcomplete canonical NodeEventをdedicated hash domain 0x000Dと
  active epoch hash suiteでdigest化する。application update、request_id/event digest/responseを持つ
  dedup record、ordered outbound messageを持つrequest-scoped outbox batchを同一commitへ含める。
  同一request/digestのretryはtransitionを再実行せずresponseだけを返し、別eventへのrequest ID
  reuseはfail closedする。native HTTPはrequest-scoped transport sendまで統合したが、providerが
  unattended outboxを発見するscheduling、retention/compaction、durable crash recoveryは未実装であり、
  request retryで回復できるだけでproduction delivery完成とはみなさない。
- outbox delivery cursorは1 messageずつnon-zero lease IDと5分以下のdeadlineでclaimし、batch
  revisionを同一transactionでassertする。matching lease/indexのackだけがcursorを進め、期限切れ
  claimは同じindexを再配信する。これはsend後ack前crashでmessageを失わないat-least-onceであり、
  exactly-onceではない。native HTTPは30秒leaseとinjected restart-safe lease ID sourceでtransportを
  driveする。nativeはStateKeyScanner pageからcompleted/tombstone/active leaseをskipし、最大1 outboxを
  同じlease/send/ack経路で処理してexclusive continuationを返すrecover_outboxes_onceを提供する。
  HTTPと同じNativeBlockingExecutorを共有し、resident loopやscheduler trustを作らない
  （implemented As-Is）。real provider trigger、trusted time policy、poison message、
  retention/compaction、durable fault testはTo-Beに残る。
- native adapterはPOST /v1/events、exact canonical binary media type、bounded body、
  deterministic HTTP status mapping、GET /health/live、graceful shutdownを提供する。
- native outbound eventはatomic commit済みoutboxからlease後にruntime transportへ渡し、send成功後
  にmatching lease/indexをackする。send failureは503とactive leaseを残し、期限切れ後のretryで
  at-least-once redeliveryする。requestなしのone-shot recovery seamは実装したが、provider scheduler
  trigger、durable SQLite runtime composition、process/power-fault conformanceは未実装である。
- TLS、authentication、rate limiting、durable StateStoreのbounded wiring、audit telemetry、reverse
  proxy hardeningは未実装であり、このAs-Is adapterをinternet-facing production serverと扱わない。
- 現在のRuntime traitは同期APIであるため、native adapterはcanonical decode、node-core、durable
  state、outbox send/ack、result encodeを1つのspawn_blocking jobへ隔離し、embedding processが
  non-zero concurrency limitを必ず指定する。permit枯渇時はadapter内でqueueせず429を返し、根拠の
  ないRetry-After値は生成しない。livenessはblocking poolから独立する（implemented As-Is）。
  開始済みspawn_blockingはTokioで
  cancelできないため、HTTP timeoutだけ先に返してcommitを裏で継続する実装は採用しない。
  structured durable pathはexplicit trusted cancellation signalをasync handler、blocking job開始、最初のstorage
  dispatch直前でのみ検査し、cancel済みなら503かつstate/receipt/outbox/send/ackなしで終了する。storage dispatch
  開始後はsignalを再検査せずcommit/send/ack reconciliationを完遂する（implemented As-Is）。client disconnect、
  started I/O cancellation、shutdown budget、load capacity、circuit breakerはTo-Beに残る。

Phase 15 To-Be production exit criteria:

1. 全NodeEvent kindについてcanonical payload schema、type/version ID、最大サイズ、
   authentication/authorization順序、state read/write set、response、outbound message、
   stable/negative vectorsをprotocol specificationとして固定する。
2. transaction、vote、certificate、consensus、governance、upgrade、validator-set、Tickの
   concrete dispatchを実装し、unknown kind/type/version/fieldと未対応機能をfail closedにする。
3. single-key state replacementを明示的atomicity domainと全read-set（read-only、absent、tombstoneを含む）
   revision assertionを持つversioned transactionへ置換する。複数object、index、consensus metadata、
   dedup record、outbox初期状態を同一commitで更新し、cross-domain writeはprotocol-level coordinationなしに
   部分成功させないproduction contractと、normalized PostgreSQL durable実装を完成させる。
4. request_idとevent digestをpersisted dedup recordへ統合し、duplicate、replay、reorder、
   timeout後retry、concurrent delivery、process crash後retryで同一effectsを二重適用しない。
5. state commitとoutbound publicationのcrash windowをtransactional outboxまたは同等の
   recovery protocolで閉じる。prefix full scanではなくbounded indexed due-work claimを実装し、
   commit済み未送信、送信済み未ack、duplicate sendを回復でき、relayをtrust rootにしない。
6. HTTP contractにmethod/path、content type、body/header limits、timeout、cancellation、
   status/error mapping、request correlation、backpressure、streaming禁止/許可範囲、
   secret-bearing response policyを明文化する。
7. CAS conflict、storage outage、signing failure、outbox failure、overloadに対するbounded retry、
   jitter、deadline、admission control、circuit breakingをadapter policyとして実装し、
   protocol transitionをretry policyから独立させる。
8. native HTTP adapterをTLS termination、authentication、rate limiting、request smuggling対策、
   decompression bomb対策、graceful shutdown、health/readiness、structured audit log、metrics、
   traces、secret/key isolationを含むproduction deploymentとして検証する。
9. supported native/edge runtime間でevent decode、context rejection、state transition、CAS conflict、
   error mapping、outbox recoveryのconformance suiteを通し、fuzz/property/adversarial/load/soak testと
   worst-case capacity budgetを固定する。
10. version upgrade、epoch rollover、schema compatibility、database migration、backup/restore、
    disaster recovery、key rotation、rollback非依存のsafe disable、operator runbook、SLO/alertを
    rehearsalし、independent security reviewを完了する。

Phase 15 persistence implementation order（To-Beからの逆算）:

1. SQLite既存dataを暗黙migrationせず、writer fence、deadline、typed conflict/indeterminate failureを持つ
   durable domain adapter boundaryを定義する（implemented As-Is; composition/provider implementation pending）。
2. indexed due-outbox repository/claim contractを追加し、domain-aware unattended recoveryを接続して
   StateKeyScannerはmaintenance/compatibilityへ戻す（contract/native/PostgreSQL implemented As-Is;
   provider durable adapters pending）。
3. `POSTGRES.md`のexact namespace、unsigned SQL representation、normalized relation、attempt history、
   transaction order、migration policyを維持する。adapterがopaque PersistenceLayout key prefixをparseせずに済むよう、
   state/object/receipt/outboxを明示的sectionとして持つstructured durable transaction envelopeを先に実装する
   （runtime/node-core/memory/native compositionとgeneration-one normalized schema migration/operator bootstrapは
   implemented As-Is; bounded pool、fenced state/body-free object head/immutable object version/receipt read、
   serializable structured state/object/receipt/outbox commit、canonical object lock order、tombstone history reconstruction、
   inline/blob lossless mapping、
   statementごとの残deadline timeout、bounded unchanged-envelope serialization retry、typed conflict/indeterminate分類も
   PostgreSQLでimplemented As-Is; indexed exact-request/due claim、same-lease reconciliation、retained attempt history、
   idempotent ack、pool/row-lock deadline exhaustionとcommit-boundary deadline classificationもPostgreSQLで
   implemented As-Is; in-flight cancellation/fault/capacity certification pending）。
   explicit migrationとshared contract evidenceはimplemented As-Is; broader fault/capacity evidenceは未実装である。
4. shared conformanceにexact deadline boundary、write skew、absent-key race、bound-domain/fence/deadline rejection、
   object read-count bound、blob-reference round-trip、object create/update/delete/recreate ABA、
   object conflict時のstate/receipt/outbox/version rollback、definite contention classification、lease fencingを追加し、
   PostgreSQL capability testにimmutable history/current/tombstone/blob mapping、head metadata corruption fail-closed、
   separate version readでのmalformed inline body fail-closed、
   pool/row-lock deadline、serialization failure、
   schema/version skewを追加する。optional shared commit-loss capabilityはbounded test-only `NoTls` TCP proxyを介し、
   plain state commitへのCOMMIT dispatch直前connection lossとinvocation commit・outbox claim・acknowledgementへの
   backend COMMIT acceptance直後connection lossを別々に注入し、いずれもIndeterminate(ConnectionLost)として
   分類されることと、前者はstate ground truth不在、後者はexact state/receipt ground truth・RequestAlreadyCommitted
   （invocation commit）を証明する。claim/ackはsame-lease/same-identity replay単独では非committedと区別できない
   ため、別lease claim probe（NoDueWork）とoriginal lease reclaim probe（LeaseIdReuse）で先にpersistedを証明した上で
   same-identity reconciliationを証明し、pool recoveryを証明する
   （memory/PostgreSQL/commit-loss capability implemented As-Is；backendの成功応答の証跡でありabrupt
   process/power lossに対するcrash durabilityの証明ではない; provider adapters、TLS-path connection loss、
   other fault/capacity certification pending）。別途、serializedなlive testがcommitted structured
   invocationの直後にdatabase-service containerを`docker kill --signal=KILL`し、restart/readiness/
   fresh connection reconciliationを検証する（implemented As-Is; ARCHITECTURE.md DR-0069）。これは
   database-process SIGKILLとWAL recoveryの証明のみであり、abrupt host/power loss、storage write-cache
   flush/torn-write/media/filesystem fault、TLS-path connection loss、capacity/load/soak、real writer
   failover、backup/restore、provider certificationは未実装である。
5. real host/power fault（storage write-cache flush、torn-write、media/filesystem fault含む）、
   commit-boundary/real storage-device ENOSPC、
   capacity/load/soak、backup/restore、writer failoverをrehearsalする。database-process
   SIGKILL/WAL recovery、bounded pre-commit data-tablespace ENOSPC（DR-0070）、bounded pre-commit
   WAL-filesystem ENOSPC（DR-0071）、bounded server connection-slot exhaustion（DR-0072）、bounded
   `pg_dump`ベースのdatabase-snapshot restore rehearsal（DR-0073）以外は
   このstep 5の全項目が未実装のまま残っている。connection exhaustionはDR-0072でserverが飽和した
   際にadapter poolがdefinite pre-commit `Rejected(DeadlineExceededBeforeCommit)`を返すことを
   bounded disposable containerで証明したが、real-device resource exhaustion、load/soak capacity、
   provider-managed pooler下での挙動、production certificationは未実装のままである。DR-0073は
   digest-pinnedなsourceとtargetの2つの独立したdisposable containerで`pg_dump --inserts`
   snapshotを取得し、PostgreSQL 18の`pg_dump`が付与する`psql`専用の`\restrict`/`\unrestrict`行
   （SQLではない）を除去した上でadapter自身のdriver connection経由で別isolated targetへ
   直接restoreし、fence promotion前にexact schema identityとrestored namespace metadata・
   state・receiptをadapterのread pathで検証し、operator-only
   `advance_writer_fence`でrestored namespaceのwriter fenceを進め、stale pre-backup context
   （旧fence）が`Rejected(WriterFenced)`でfail closedし、新fenceのfresh contextがexact
   restored state/receiptをreconcileし、identical invocationで`RequestAlreadyCommitted`を
   観測してからexact pending outbox payloadのclaim/ackを完了して
   新規workをcommitできることを証明した
   （bounded database-snapshot restore rehearsal evidenceのみimplemented As-Is; ARCHITECTURE.md
   DR-0073）。このtarget側だけのfence advanceは独立して動き続けるsource databaseを停止・
   fenceしないためsingle-writer failoverの証拠ではない。negative pairではrequiredな
   `storage_metadata`の`CREATE TABLE`途中でcutしたdumpがsingle simple-query batchとしてatomicに
   failしschema markerを残さないことと、fixtureの`state_records` insertだけを除いたvalid dumpが
   schema・namespace metadata・receiptをrestoreしながらmissing stateによってdeeper rehearsal
   verification gateを通過しないことを証明する。これは1回の`pg_dump`/SQL-execute
   snapshot cycleに対するrehearsal evidenceに過ぎず、production backup/restore機能ではない。
   point-in-time recovery、continuous WAL archiving、concurrent write負荷下でのhot backup、
   `pg_basebackup`/replicationベースのbackup、backup encryption/off-host storage、
   retention/rotation policy、restore automation、checkpoint publication（schemaには
   checkpoint publicationの実装がなく、`sunrise_edge.checkpoints`はこのcrateのどこからも
   書き込み・読み取りされていない）、blob-manifest/state-root/encryption-key verification、
   multi-database/whole-cluster backup、concurrent adapter write traffic下でのbackup、
   real storage-device/off-host transfer fault、production certificationは未実装のままであり、
   backup/restore評価基準を閉じるものではない。
6. 同じcontractをCloudflare Durable ObjectとAWS persistenceへ実装し、real providerでcertifyする。

Phase 16:
- Cloudflare Workers ingress adapter (implemented As-Is)

Phase 16 As-Is scope:

- ES module WorkerがPOST /v1/eventsとGET /health/liveをPhase 15 contractと同じpath、
  exact media type、identity-only content encoding、no-store semanticsで提供する。
- request bodyはReadableStreamから固定上限までだけ読み、unbounded arrayBuffer/text/JSON
  bufferingを行わない。
- node-core serviceはpublic URLではなくgenerated Env.NODE_CORE Service Bindingでawaitして呼ぶ。
- module-level mutable request state、floating Promise、Cloudflare REST API、hardcoded secret、
  passThroughOnExceptionを使用しない。
- downstream response headerをallow-listで再構築し、binding内部500をsanitized 502へ変換する。
- wrangler.jsoncはtested workerdがsupportする最新compatibility date、nodejs_compat、
  observabilityを固定し、binding typeはwrangler typesで生成する。
- workerd integration testはmock Service Bindingでsuccess、liveness、method/media/encoding、
  declared/streamed oversize、downstream failureを検証する。
- toolchain compatibility debtとして、project typecheckは`typescript-7` aliasのTypeScript 7.0.2を
  使用し、`typescript-eslint` 8.xのpeer rangeを満たすTypeScript 6.xはESLint parser専用に隔離している。
  `typescript-eslint`がTypeScript 7を正式supportした時点で、通常の`typescript` dependencyを
  TypeScript 7へ統一し、`typescript-7` aliasと一時的なTypeScript 6.xを削除する。その変更は
  forced peer resolutionを使わず、ESLintのtype-aware rulesとrepository全gateの通過を必須とする。
- 現実装はbounded ingress/relayだけであり、Cloudflare上でnode-core transitionやdurable stateを
  実行するproduction validatorの完成形ではない。

Phase 16 To-Be production exit criteria:

1. NODE_CORE serviceのdeployment architectureを固定し、Worker/WASM、Durable Object、
   Workflows/Queues、外部durable storeの責務とtrust boundaryをprotocol/runtime仕様へ接続する。
2. atomic multi-key state、persisted deduplication、transactional outbox、crash recoveryを
   Cloudflare binding/storage semantics上で実装し、duplicate/replay/concurrent invocationで検証する。
3. Cloudflare Access contextがService Binding先へ自動伝播しない前提で、public ingress認証、
   protocol署名検証、service capability、operator/admin routeを分離しfail closedにする。
4. WAF、API Shield、rate limiting、bot/DDoS policy、request/header limits、custom domain/TLS、
   Cache RulesをIaC化し、dashboard driftとsecretのsource管理混入を防ぐ。
5. CPU/memory/subrequest/invocation limits内のworst-case event benchmark、load/soak test、
   backpressure、bounded concurrency、deadline、cancellation、overload behaviorを固定する。
6. structured logs、traces、metrics、request correlation、sampling、PII/secret redaction、SLO、
   alert、cost guardrailをproduction observabilityとして実装する。
7. compatibility_date、Wrangler、workerd、generated types、service versionをrelease artifactへ固定し、
   staged rollout、version skew、rollback非依存safe disable、binding target切替をrehearsalする。
8. native adapterとのcanonical/status/error conformance、real binding integration、fault injection、
   fuzz/adversarial/security test、independent review、operator/disaster-recovery runbookを完了する。

Phase 17:
- Vercel / Supabase / AWS / Deno adapters

Phase 17 prerequisites:

- provider-neutral Web Fetch API ingress core (implemented As-Is)
- Cloudflare conformance consumer over the shared implementation (implemented)
- provider-specific lower request capacity policy (implemented As-Is)
- shared authenticated HTTPS node-core capability (implemented As-Is)
- Deno adapter wrapper (implemented As-Is)
- Vercel adapter wrapper (implemented As-Is)
- Supabase Edge adapter wrapper (implemented As-Is)
- AWS adapter wrapper and API Gateway HTTP API v2 mapping (implemented As-Is)
- cross-provider local ingress fixture matrix (implemented As-Is)
- repository-wide pinned local/CI validation gate (implemented As-Is)
- reviewed weekly dependency/action update proposals (implemented As-Is)

Phase 17 shared ingress As-Is scope:

- provider wrapperはNodeCoreFetcher capabilityだけを注入し、path、media type、body limit、
  stream read、status mapping、downstream validation、header sanitizationをshared moduleから使う。
- shared moduleはenvironment lookup、provider SDK、credential、retry loop、durable state、
  mutable global request stateを持たない。
- provider wrapperは認証/private transportを追加できるが、shared boundやfail-closed mappingを
  緩めたりprovider独自wire contractへforkしてはならない。
- provider platform limitがshared request boundより小さい場合だけ明示的なlower boundを設定できる。
  zero、非整数、shared上限超過はconfiguration errorとして拒否し、security boundの引上げを許さない。
- private service bindingを持たないWeb provider向けの暫定transportはexact HTTPS endpoint、
  allow-listed header、bounded ASCII Bearer secret、redirect拒否、1..30000ms timeoutを一実装にする。
  environment lookupとprovider credential lifecycleはこのmoduleへ入れない。
- 現在のAs-Is consumerはCloudflare workerd、local Deno runtime、local Vercel/Supabase wrapper、
  AWS HTTP API v2 mapper testであり、real provider deployment conformanceはまだ完了していない。
- liveness、unknown path、method、media parameter、content encoding、content-lengthの同一fixtureを
  5 provider consumerで実行する。これはlocal drift検出であり実gateway/runtime conformanceではない。
- Rust 1.97.1、Node 22.20.0、Deno 2.9.4を固定したcheck script/CIがRust全featureと全adapterを
  一括実行する。CI actionもverified upstream tagのcommit SHAへ固定するが、provenance、SBOM、
  reproducibility、real provider testは未完了である。
- DependabotはCargo、Cloudflare npm、GitHub Actionsを週次確認し上限付きPRを作るがauto-mergeしない。
  changelog/互換性/repository gateを人がreviewする運用の強制、provenance検証、緊急更新SLAは未完了である。

Phase 17 Deno As-Is scope:

- current Deno 2 / Deno Deploy向けdefault fetch exportがshared ingress handlerをそのまま使用する。
- node-core endpointはexact HTTPS /v1/eventsに限定し、userinfo、query、fragment、redirectを拒否する。
- Deno Deploy secretからbounded Bearer capabilityを注入し、source、response、structured errorへ
  secretを出さない。downstream timeoutは1..30000msの固定上限でfail closedにする。
- provider wrapperはcanonical bodyをdecodeせず、path、media type、body bound、status、response headerを
  forkしない。testはpermission-free mock fetchでshared rejectionとauthenticated forwardingを検証する。
- 現実装はpublic HTTPS endpointへのBearer-authenticated relayであり、private connectivity、mTLSまたは
  signed service request、rotation/revocation、durable deduplication/outbox、real Deno Deploy rehearsalを
  production完成とみなさずTo-Beに残す。

Phase 17 Vercel As-Is scope:

- current Vercel Node.js FunctionのWeb fetch exportを使用し、canonical 2 pathを単一handlerへrewriteする。
- documented 4.5 MB Function payload ceilingより小さい4 MiB request budgetをshared lower-bound policyへ
  渡し、declared/streamed oversizeをnode-core forwarding前に413とする。
- Sensitive Environment VariableのBearer capability、exact HTTPS endpoint、redirect拒否、bounded timeoutは
  shared authenticated transportを再利用し、provider固有のcanonical decodeやstatus mappingを作らない。
- 現実装はpermission-free local wrapper testまでで、Vercel preview/production deployment、rewrite後の
  original path保持、platform 413/504、response 4.5 MB ceiling、Fluid Compute lifecycleは未検証である。
- 4 MiBはprotocol transport上限より小さいためfull conformanceではない。全valid eventを受理できる
  ingress architecture、private/mutual authentication、rotation、durable outbox等をTo-Beに残す。

Phase 17 Supabase As-Is scope:

- `sunrise-edge` Edge Functionのdefault fetch exportを使用し、gatewayがfunctionへ見せる
  `/sunrise-edge/*` prefixをcanonical 2 pathにだけexact matchで除去してshared handlerへ渡す。
- `supabase/config.toml`で`verify_jwt = true`を明示し、eventとlivenessの両方を現在はgateway JWT必須にする。
  public healthとauthenticated submissionの分離は認証を暗黙disableせずproduction設計へ残す。
- outboundはshared exact HTTPS/Bearer/redirect/timeout capabilityを再利用し、secret名はreserved
  `SUPABASE_` prefixを使わない。canonical bodyのprovider decodeや独自status mappingを追加しない。
- hosted limitsに256 MB memory、2秒CPU/request、150秒idle timeoutはあるが、同じ公式limit pageに
  payload ceilingはないため根拠のないprovider boundを設定せずshared boundを維持する。
- 現実装はpermission-free local wrapper testまでで、Supabase CLI/local gateway/hosted deploy、JWT
  claims policy、gateway 401/413/504、isolate reuse、real capacityは未検証としてTo-Beに残す。

Phase 17 AWS As-Is scope:

- API Gateway HTTP API payload format 2.0 eventだけをtyped validationし、method、rawPath、lowercase
  headers、base64 bodyをWeb Requestへ変換してshared handlerへ渡す。1.0やmalformed eventは拒否する。
- canonical event POSTはstrict canonical base64を必須にし、encoded lengthをdecode前に検査する。
  shared contractが使うcontent-type/content-encoding/content-length以外のheaderを再構築しない。
- API Gateway 10 MBに対しsynchronous Lambda request/buffered responseはJSON envelope込み6 MBのため、
  request/responseとも保守的4 MiB budgetとし、全protocol-valid envelope対応とは主張しない。
- Lambda proxy resultはcanonical binaryを壊さないよう常にbase64 responseとし、responseもbounded read、
  header allow-list、oversize 502でfail closedにする。
- control-plane SDKやunauthenticated IaCを含めない。payloadFormatVersion 2.0、JWT scope/IAM/custom
  authorizer、VPC/private transport、Secrets Manager/KMS、reserved concurrency/throttle/WAF、real deploy、
  platform retry/durability/observabilityはTo-Beに残す。

Phase 17 To-Be production exit criteria:

1. Deno、Vercel、Supabase、AWSそれぞれでpublic ingress、private node-core transport、
   authentication、secret/key、durable state、outboxのdeployment architectureを固定する。
2. shared ingress contractの同一fixtureを全provider実runtime/emulatorで実行し、path/media type、
   bounds、stream cancellation、status/error、header sanitization、canonical bytesを一致させる。
3. 各providerのbody/header/CPU/memory/duration/concurrency/subrequest limitを取得・固定し、
   shared protocol limitより小さい場合の明示的413/429/503 behaviorとcapacity budgetを定める。
4. freeze/thaw、isolate reuse、cold start、concurrent invocation、client cancellation、timeout、
   platform retryでprocess memoryをprotocol stateにせず、duplicate effectsを発生させない。
5. public URLへの無認証node-core forwardingを禁止し、service/private network/mTLS/signed request等の
   provider別capabilityを実装する。secretをsource/config/logへ残さずrotationをrehearsalする。
6. provider固有log/trace/metricを共通correlationとSLOへ接続し、redaction、sampling、alert、
   cost/abuse guardrail、cross-provider incident responseを実装する。
7. IaC、runtime/toolchain/version lock、staging/canary、schema/version skew、safe disable、
   disaster recovery、provider outage時のrouting policyをrelease procedureとして固定する。
8. fuzz/adversarial/load/soak/fault-injection test、dependency/SBOM/reproducible build、
   independent security review、provider別operator runbookを完了する。

Cross-phase production release gate（最後まで延期する単独Phaseではなく常時適用）:

- Coding RequirementsとSecurity Invariantsを全crateで満たす。
- experimental/deferred/mock/temporary項目に未充足のproduction exit criteriaがない。
- protocol specification、migration/activation procedure、disaster recovery、monitoring、
  capacity planning、key management、validator operationsを再現可能に文書化する。
- supported runtime間でcanonical bytes、digests、execution effects、commitments、
  consensus outcomes、proof verificationが一致する。
- fuzz/property/adversarial/long-running testsと第三者security auditの重大指摘を解消する。
- mainnet genesis前にrelease artifact、dependency、compiler、build provenanceを固定し、
  reproducible buildとupgrade rehearsalを完了する。


# 66. Architecture Documentation

実装前にARCHITECTURE.mdを作成してください。

最低限以下を明文化する:

1. overall architecture
2. crate boundaries
3. canonical serialization rules
4. hash architecture
5. HashSuite lifecycle
6. hash domain separation
7. commitment scheme architecture
8. signature domain separation
9. Object lifecycle
10. Transaction lifecycle
11. Fast Path lifecycle
12. Certificate lifecycle
13. persistent state layout
14. validator lifecycle
15. Genesis bootstrap
16. bond lifecycle
17. slashing lifecycle
18. stablecoin fee lifecycle
19. governance lifecycle
20. epoch transition
21. protocol upgrade lifecycle
22. hash algorithm migration lifecycle
23. System Module lifecycle
24. WASM / Chain IR execution
25. ZK execution architecture
26. security invariants
27. failure scenarios
28. serverless runtime constraints


ARCHITECTURE.md完成後は停止せず、
そのまま実装してください。

各Phaseごとに:

cargo fmt --check
cargo clippy --all-targets --all-features
cargo test --all

を通してください。

architecture上の矛盾を発見した場合は、
場当たり的なhackを入れず、
ARCHITECTURE.mdへdecision recordを追加してから修正してください。


# 67. Highest Priority

architectureの中心に置くもの:

- Serverless-native validator
- No daemon requirement
- Object-centric state
- ABI-driven parallel execution
- Fast path for non-conflicting transactions
- Deterministic WASM
- Rust-first smart contracts
- Native-token-independent security
- Permissioned genesis bootstrap
- Stablecoin validator bonds
- Bond amount independent from voting power
- Stablecoin transaction fees
- Direct validator fee revenue
- Dynamic governance-installed system modules
- Protocol upgradeability
- Cryptographic agility
- Self-describing digests
- Strict domain separation
- SHA-256 as conservative Genesis general-purpose hash
- SHA3-256 supported as migration alternative
- No per-transaction hash negotiation
- No global rehash migrations
- Separate general-purpose hash and ZK commitment schemes
- Lazy state migration
- ZK-friendly execution
- Multi-cloud / edge portability

最重要の思想は以下です。

"A blockchain node is not a continuously running server.
It is a deterministic state-transition function over cryptographically authenticated events and persistent state."

また暗号設計については、

"Hash algorithms are agile, but never negotiable per transaction."

を原則としてください。

高速性だけを理由に暗号primitiveを選定せず、
保守性、標準化、長期互換性、algorithm migration、
domain separation、canonical encoding、ZK suitabilityを
用途ごとに評価してください。
