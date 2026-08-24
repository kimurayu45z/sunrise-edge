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
- node-coreのtransactional pathはcontext検証後かつstate read前にevent-specific access planを
  確定し、全keyをrevision付きsnapshotとしてpure transitionへ渡す。undeclared/read-only updateを
  rejectし、観測revisionをnode-core自身がwrite-setへbindし、全commit成功までoutputを返さない。
  現行adapterはlegacy single-key pathのままで、dedup/outboxとdurable recoveryも未実装である。
- native adapterはPOST /v1/events、exact canonical binary media type、bounded body、
  deterministic HTTP status mapping、GET /health/live、graceful shutdownを提供する。
- outbound eventはCAS成功後にruntime transportへ渡すが、state commitとsendの間はまだ
  atomicではない。send failureが503を返してもstateがcommit済みの場合があるため、
  productionではpersisted deduplicationとtransactional outboxが必須。
- TLS、authentication、rate limiting、durable StateStore、audit telemetry、reverse proxy
  hardeningは未実装であり、このAs-Is adapterをinternet-facing production serverと扱わない。
- 現在のRuntime traitは同期APIであるため、遅いdurable I/OをTokio request task上で直接行う
  production実装にしない。async runtime boundaryまたは明示的なbounded blocking isolation、
  concurrency limit、deadlineを設計する。

Phase 15 To-Be production exit criteria:

1. 全NodeEvent kindについてcanonical payload schema、type/version ID、最大サイズ、
   authentication/authorization順序、state read/write set、response、outbound message、
   stable/negative vectorsをprotocol specificationとして固定する。
2. transaction、vote、certificate、consensus、governance、upgrade、validator-set、Tickの
   concrete dispatchを実装し、unknown kind/type/version/fieldと未対応機能をfail closedにする。
3. single-key state replacementをversioned atomic write-setへ置換し、複数object、index、
   consensus metadata、dedup recordを同一commitで更新できるproduction StateStore transaction
   contractと少なくとも1つのdurable実装を完成させる。
4. request_idとevent digestをpersisted dedup recordへ統合し、duplicate、replay、reorder、
   timeout後retry、concurrent delivery、process crash後retryで同一effectsを二重適用しない。
5. state commitとoutbound publicationのcrash windowをtransactional outboxまたは同等の
   recovery protocolで閉じる。commit済み未送信、送信済み未ack、duplicate sendを回復でき、
   relayをtrust rootにしない。
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
