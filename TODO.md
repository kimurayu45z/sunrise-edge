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

## CLI Developer MVP Gate

**CLI-first production戦略への転換（本節およびTODO全体でこの決定を"pivot"と呼ぶ）。**
旧`Developer MVP Gate`は、TypeScript client・explorer・walletというブラウザ向け
product surfaceの完成をsingle-node MVPのgoalに含めていた。この転換では、gate自体を
`CLI Developer MVP Gate`と改名し、このgateのgoalをcriteria 1-6・10・11（native devnet、
authenticated owned object Read/Write/Consume、preinstalled deterministic WASM、bounded
query API、Rust client library、Rust-only CLI、restart/duplicate E2E、明示的な
non-production limitations）だけに絞る。criteria 7-9（TypeScript client、explorer、
wallet）はverbatimのまま以下に残すが、完了済み・削除済み・弱められたとは一切みなさず、
新設する["CLI-First Node Production Gate"](#cli-first-node-production-gate)を通過した
"後に"resequenceする。この転換はbrowser向けproduct surfaceを断念するものではなく、
本物のnodeのproduction hardening（persistence、operations、release evidence）を
ブラウザ向けUIより先に固めるという順序の変更である。

Phase 15-17のproduction hardeningを先へ積み上げる前に、Rust client libraryとRust-only
developer CLIを実際に構築・検証できるsingle-node CLI Developer MVPを完成させる。
このgateはproduction readinessやmainnet readinessを意味せず、既存のTo-Be criteriaを
削除しない。MVP correctnessを直接妨げる場合を除き、追加のcapacity/load/soak、PITR、
HA/failover、provider-managed pooler、real-provider certification、provider deploymentの
作業はgate通過後の`Post-MVP Production Hardening`へ凍結する。

**Current status (2026-09-04): criteria 1-6・10・11はimplemented and validated
As-Isであり、CLI Developer MVP Gateは通過済みである。** これはproduction readinessの
宣言ではない。CLI-First Node Production GateのS0-S3もimplemented and validated
As-Isであり（S1のremote TLS transportとsigning前の独立したtrusted
protocol-context validationの両方。詳細は
["CLI-First Node Production Gate"](#cli-first-node-production-gate)のS1参照）、
S2のcross-owner destination policyはDR-0086、S3のuniform ordinary-asset fee
composition・actual-gas/trap settlement・real restart/replay E2EはDR-0087のとおり
implemented As-Isである。S4a hardware-signing profile/host preflightもDR-0088のとおり
implemented As-Isであり、DR-0089はS4b device contract（`SIGNING.md`のSLIP-0010 derivation・
public key encoding・status word分離・device-side sender比較・device policy pin・
duplicate ObjectId rejectionなど）をclarifyし、加えてDR-0088のsign transaction全体
230-byte APDU capをFIRST最大255-byte・first chunk最大230-byteへ訂正した
（continuation chunkは230-byteのまま不変。Sunrise canonical transaction/signature
bytesやこのrepositoryの実装コードの変更はない）。DR-0090により、separate
`sunriselayer/sunrise-edge-ledger-app` repositoryのPR #1ではallocation-free `no_std`
APDU state machine・independent canonical parser・exact policy recognition・signed-fields
review model・copied stable fixture conformanceからなるhost-validated coreがimplemented and
validated As-Isになった。ただしLedger SDK binary・SLIP-0010 derivation・Ed25519 signing・
on-device UI・APDU/USB/HID transport・Speculos/reproducible-build/physical-device evidenceは
存在せず、S4b/S4は引き続きincompleteである。現在のimplementation priorityはactual
dedicated Ledger device integration/Speculosである。TypeScript client/explorer/walletと
S5は引き続きdeferredであり、S5は順序を飛ばさず後続する。

CLI Developer MVP completion criteria（capability criteria 2-3を満たしながら、product
surfaceはARCHITECTURE.md DR-0081の順序に従う: local devnet、bounded query API、Rust
client、Rust CLI、TypeScript client、explorer、wallet、restart/duplicate E2E、
explicit dev limitations）。**pivot後のgateはcriteria 1-6・10・11だけであり、
criteria 7-9（TypeScript client、explorer、wallet）はverbatimのまま以下に残すが、
["CLI-First Node Production Gate"](#cli-first-node-production-gate)を通過するまで
明示的にdefer/resequenceする（削除・完了扱い・弱体化ではない）:**

1. native HTTPとlocal durable SQLiteを使い、停止・再起動できるsingle-node local devnetを
   documented commandで起動できる。
2. authenticated owned inline objectのRead/Write/Consumeを実行し、signed accessと
   deterministic `ObjectEffect`を厳密に対応付け、nonce、application state、object head/version、
   receipt、outboxを同じdurable invocationでatomic commitする。Create、Shared/System owner、
   blob-backed bodyは明示的にfail closedのままでよい。
3. governed/preinstalled moduleをexact commitmentからloadし、bounded deterministic WASMで
   少なくとも1つのstateful contractを実行できる（devnetの具体的なmoduleは
   `sunrise.devnet.asset_account.v1`の`transfer` entrypoint。DR-0081参照）。任意upload、JIT、
   production meteringはMVP範囲外とする。
4. chain/context情報、object、receipt、authenticated senderのnext nonceを取得するbounded
   query APIを提供する。
5. `clients/rust`でkey/address、canonical transaction encode/sign、submit、receipt wait、
   queryを提供するRust client libraryを実装し、serverのcanonical contractに対する
   stable vectorsを共有する。
6. `clients/rust`のみに依存するRust-only developer CLI（`apps/cli`）を実装する。
   `apps/cli`はNode/browser runtimeに依存せず、canonical encode/decode・signing・RPC呼び出しは
   すべて`clients/rust`経由とする。
7. `clients/typescript`でkey/address、canonical transaction encode/sign、submit、
   receipt wait、queryを提供するTypeScript client libraryを実装し、同じstable vectorsを共有する。
   **（pivot後: この criterion のcontentは変更しない。実装着手は
   ["CLI-First Node Production Gate"](#cli-first-node-production-gate)通過後まで
   deferする。）**
8. `apps/explorer`として、SvelteKit + shadcn-svelte（Luma）によるstatic/CSR専用のexplorer app
   を実装する。request-time server-side rendering、SvelteKit server adapter、
   `+page.server`/`+layout.server`/`+server` route、server actions/remote functions/
   server-held sessionやkeyは一切使わない。dynamic chain dataは`clients/typescript`経由の
   client-side fetchのみとする。
   **（pivot後: この criterion のcontentは変更しない。実装着手は
   ["CLI-First Node Production Gate"](#cli-first-node-production-gate)通過後まで
   deferする。）**
9. `apps/wallet`として、同様にSvelteKit + shadcn-svelte（Luma）によるstatic/CSR専用のwallet app
   を実装する。制約は8と同一（SSR/server adapter/server route/server actionsなし）に加え、
   signing keyはbrowser内でのみ生成・保持・使用し、server側へ渡したり生成させたりしない。
   `apps/explorer`と`apps/wallet`の間でreal duplicationが発生するまで、共有UI packageは
   導入しない。
   **（pivot後: この criterion のcontentは変更しない。実装着手は
   ["CLI-First Node Production Gate"](#cli-first-node-production-gate)通過後まで
   deferする。）**
10. devnet再起動後もstate/object/receipt/nonceが保持され、同一request retryがeffectを
    二重適用しないことを自動E2Eで証明する（`apps/cli/tests/devnet_restart_duplicate_e2e.rs`
    でimplemented As-Is。real file-backed `SqliteDurableStore`、composeしたdevnet router、
    real loopback TCP、`sunrise-edge-cli::run`によるuser-facing transferと
    `sunrise-edge-client`による独立検証を使い、orderly stop/reopen後のobject・receipt・
    next-nonce query resultとsubmit resultのcanonical bytes一致、same-bootおよび
    restart後のbyte-identicalなsuccessfulおよびtrapped fee-only duplicate submissionの
    非再適用、actual `gas_used`に一致するordinary asset fee debit/treasury credit、
    already-committedな
    request idの別transactionでの再利用がfail closedになること、pre-restart writer
    generationがreopen後にfencedであることを証明する。orderly stop/reopenのみの証明であり、
    `kill -9`、power loss、torn write、load、concurrency、SQLiteのproduction適性は
    証明しない。下記S0参照）。
11. single validator、owned-object only、1つのfixed ordinary fee assetとdistinct ordinary
    treasury（validator/certificate distributionやproduction economicsなし）、local SQLite、
    cross-owner movementはexact committed destination policyだけ（literal owner reassignment/
    giftingはfail closed）、4 bounded query routeがunauthenticated public-read API（呼び出し元は誰でも
    任意のobject/receipt/next-nonce/contextを読める。`/v1/senders/{sender}/next-nonce`の
    addressはpublic lookup selectorでありauthorizationではない）であること、queryと
    submissionが単一の共有admission budget（`NativeBlockingExecutor`／
    `--max-concurrent`）を使う（片方のtrafficがもう片方をstarveしうる）こと、
    non-production security/operationsという制約をREADMEと起動時表示へ明記する。

現在のMVP実装順序:

1. verified owned-object inputとdeterministic effectのfail-closed対応、およびruntime durable
   mutationへのpure translation（implemented As-Is）。
2. trusted executionから得たWrite/Consume effectsをstructured durable invocationへ接続し、
   exact object head assertionとmutationをnonce/state/receipt/outboxとatomic commitする
   additive node-core entrypoint（implemented As-Is）。generic/read-only経路
   （`structured_durable_router`を含む）は引き続きWrite/Consumeをstorage I/O前に拒否する
   （step 4の`preinstalled_wasm_structured_durable_router`のみ例外）。
3. committed `ProtocolConfig`から固定したactive system-module registryとbounded immutable
   preinstalled catalogのcode/manifest/semantics commitmentを照合し、object-onlyの
   deterministic WASM executionをowned-effects atomic durable entrypointへ接続する
   （implemented As-Is in node-core）。code/manifestはcommitted digest自身のalgorithmで再検証し、
   epoch-only hash-suite rotation後もreadableとする。専用`SystemModuleManifest` hash purpose、
   pre-activation gas ceiling、engine-independent trap normalizationを適用し、canonical
   `ExecutionEffects`をresponseへ返す。trapはobject mutationなしのRejected receipt/nonceとして
   commitする。zero-object callはこのMVP pathでは明示的に拒否する。native HTTP wiringはstep 4で
   実装済み（implemented As-Is）、devnet binary/startup wiringもstep 5で実装済み。
4. DR-0078のpreinstalled-WASM entrypointを新しいadditive `native-http`合成
   （`preinstalled_wasm_structured_durable_router`/`_with_executor`）経由でHTTPへ公開する
   （implemented As-Is）。既存の`structured_durable_router`はread-only entrypointのまま変更しない。
   両routerは認証済み準備・storage context構築・exact request-scoped outbox claim/send/ack pathを
   共有する1つのprivate core（`invoke_structured_durable_event_with_execution`）を、小さなprivate
   `StructuredDurableAuthenticatedExecution` policy enum（`ReadOnly`/`PreinstalledWasm`）で
   parameterizeして再利用し、重複させない。両axum handlerも1つのprivate
   `submit_structured_durable_event_common`ヘルパーへ統合し、content-type/body抽出/admission/
   cancellation観測/blocking dispatchの重複を排除した。新しいpublic `PreinstalledWasmComposition`は
   `Arc<PreinstalledModuleCatalog>`・zero-sizedな`execution::WasmExecutionEngine`・
   `created_checkpoint: u64`のみを保持するcomposition-trusted inputで、HTTP request bytesや
   wall clockからは決して取得しない（`created_checkpoint`はmutate対象objectについてrestart間で
   non-decreasingでなければならず、regressionはfail closedになるとdoc化済み）。新routerの
   `SubmitTransaction`は
   `handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`を
   呼び、他のevent kindは既存のgeneric machine pathのままとする。blocking admissionと
   pre-storage-dispatch cancellationは両routerで同一のsemanticsを保つ（新routerの3つの
   pre-storage checkpointすべてで直接cancellation testを追加済み）。coarse HTTP error
   classificationを拡張し、`execution::ExecutionError`をワイルドカードなしで明示的にmatchする。
   malformed/inactive/unknown module reference（`MissingEntrypoint`含む）とargs/gas/
   zero-object/resource-limit requestは引き続きdeterministic client error（422/400）、
   `WasmEngine`（trusted catalog code）と内部encoding/hash/context failureはopaque 500 host
   failure、catalog/commitment mismatchと`ObjectCreatedCheckpointRegression`はhost/operator
   failure、`ObjectCreationUnsupported`は501、`ObjectVersionOverflow`（node-core/execution両方）は
   409、`ObjectEffectMismatch`はopaque 422、`DuplicateObjectEffect`/`TooManyObjectEffects`/
   `UndeclaredObjectEffect`/`ObjectMutationContextMissing`/`SystemModules`はopaque 500
   invalid-outputとして分類する（内部詳細はleakしない）。fixtureはすべて
   `HashSuiteResolver`/canonical encoderから計算し、pasted digestを使わない。discriminating
   missing-entrypoint test（422、no receipt/mutation）とcatalog code-hash mismatch test
   （opaque 500）をHTTPレベルで追加済み。full composition-time registry/catalog reconciliation
   はdevnet compositionへ延期し、request-time mismatchは引き続きfail-closed 500とする。Create、
   Shared/System、blob、native binary/devnet startup wiring、query API、TypeScript client、UI、
   arbitrary upload、fees/meteringは引き続きこのstepの範囲外（Shared/System/blob coverageは
   node-core側に留め、HTTP層で重複させない）。
5. local devnet、bounded query API、Rust client（`clients/rust`）、Rust CLI（`apps/cli`）、
   TypeScript client（`clients/typescript`）、explorer（`apps/explorer`）、wallet
   （`apps/wallet`）、restart/duplicate E2E、explicit dev limitationsの順に追加する
   （DR-0081；旧DR-0080の`clients/typescript`/`demo/counter`という組み合わせを置き換え、
   `demo/counter`は作成しない）。devnetの最初のstateful preinstalled moduleは
   `sunrise.devnet.asset_account.v1`（`transfer` entrypoint）とし、同一senderが所有する
   2つのordinary asset-account objectの間でのみ残高を移動する。fees::AssetIdを使った
   real 32-byte asset識別、conservation、amount underflow/overflow/asset ID mismatchの
   fail closedを満たす。destination側owner authorizationとowner変更は既存のowned-effects
   pathで引き続きfail closedのため、このMVPはsame-sender movementのみを示し、
   user-to-user transferではない。devnetのfee registryは空のままとし、すべてのtransactionは
   `fee_payment: None`でcommitする（fee assetもordinaryなasset accountの上のprotocol policyに
   過ぎず、native coinや別実装のbalance/transfer/fee pathを持たない。DR-0081参照）。
   **DR-0086 amendment（current status）：** 直前のsame-sender-only/cross-owner
   fail-closed記述はDR-0081当時のMVP境界を記録したhistorical textであり、現在の実装状況ではない。
   S2はexact committed policyで既存の別Address-owned destinationを許可し、source/destination
   ownerをどちらも保存する形でimplemented and validated As-Is。literal owner reassignment/
   giftingは引き続きdeferredかつfail closedである。
   **DR-0087 amendment（current status）：** 直前のempty fee registry/
   `fee_payment: None`記述はDR-0081当時のhistorical MVP境界であり現在の実装状況ではない。
   S3は同じordinary `AssetAccount`/`DEVNET_ASSET_ID`をfee object/assetとして使い、distinct
   treasury ownerのordinary destinationへactual `gas_used`由来feeをatomic settlementする。
   active module/semanticsはv3、historical v1/v2 bytesとWAT/WASM/code hashは不変である。
   S4a hardware-signing profile/host preflightはDR-0088で後続実装済み。DR-0089はS4b device
   contractを`SIGNING.md`上でclarifyし、DR-0088のAPDU 230-byte capをFIRST最大255-byte・
   first chunk最大230-byteへ訂正した（continuationは230-byteで不変）。DR-0090により、merge
   済みseparate `sunrise-edge-ledger-app` repositoryのPR #1はhost-validated `no_std` coreを
   As-Isで提供するのみで、Ledger SDK device app・実際のSLIP-0010 derivation/signing・
   on-device UI・APDU/USB/HID transport・Speculos・reproducible device build・physical
   evidenceはまだ存在しない。S4b/S4は引き続きincompleteであり、次はactual device
   integration/Speculosである。TypeScript client/explorer/walletとS5は引き続き既存の順序で
   deferredである。production/mainnet readinessは未達である。
   前提として、`runtime-sqlite`へ`StructuredDurableDomainStateStore`/`IndexedOutboxRepository`を
   実装するadditive、local-only、non-productionな`SqliteDurableStore`を追加済み
   （implemented As-Is）。既存のopaque `SqliteStateStore`とは別テーブル・別`PRAGMA application_id`で、
   opaque state-keyのprefixを型付きレコードへ再解釈しない。`application_id`はファイル単位の
   SQLiteプロパティのため、両ストアは同一ファイルを共有できず、それぞれ別ファイルを必要とする。
   one trusted bound `(chain, validator, atomicity domain)` namespace、永続化されたfenced writer
   generation、deadline check、object/receipt/outbox/stateのatomic commit、immutable object
   version、indexed request/due outbox claim、idempotentなacknowledgementをprocess-local mutex +
   1つのSQLite transaction（複数statementから成るreadはmetadata/fence checkとpayloadを1つの
   snapshotで観測する`Deferred` transaction、writeは`BEGIN IMMEDIATE`）の上に実装。`advance_writer_fence`
   はoperator-only seamとしてBEGIN IMMEDIATE内でschema identityとchain/validator/domain
   namespaceを再検証してからfenceを読み書きする。各transaction開始前にcaller側の残り
   deadlineをそのconnectionのSQLite busy_timeoutへ伝播し、`[1ms, 5000ms]`にclampする。writer
   fenceはBEGIN IMMEDIATE直後に一度だけ検証され、write lockによりCOMMITまで有効性が保たれる
   （COMMIT直前に再検証されるのはdeadlineのみ）。digest・canonical record type ID・outbox
   attempt status・boolean列は型付き内部表現ですべて厳密にdecodeし、不明なalgorithm、長さ
   不一致、algorithm/bytesの片方欠落、想定と異なるtype ID、未知のoutbox attempt status、0/1
   以外のcompleted値、current専用列を持つtombstoneはすべてInvalidPersistedStateとしてfail
   closedする。object versionのprovenance chainはbound namespaceのchainとcommit時・read時の
   両方で照合する。current object headはexact validated immutable version rowと突き合わせ、
   それがmaximum retained versionであることとdigestの一致を確認してから信頼する
   （load_object_headはload_object_versionを呼ぶだけで、再帰はしない）。PostgreSQLと共有する
   conformance suite、実際のdurable state read/mutation・exact request replayでの
   `RequestAlreadyCommitted`・reopen後のoutbox acknowledgement冪等性を含むrestart persistence
   test、short deadlineがfixed busy timeoutを待たないことを示すbounded contention testで検証済み。
   corruption testはrepresentativeなstrict-decode/cross-checkルールを検証するものであり、
   すべてのルールを網羅しているわけではない。native-http経路への接続はstep 4で実装済み
   （implemented As-Is）。`apps/devnet`はstrict config、SQLite writer-fence boot、restart-safe
   identity source、canonical asset-account codec/stable vector、preinstalled WASM/catalog、
   2-accountのatomicかつrestart-idempotentなseed、同じin-process artifactから構成した
   registry/catalog commitmentのstartup整合性検証、
   bounded native routerのstartup wiringまで実装済み（implemented As-Is）。binaryはloopbackで
   HTTPをserveし、live smokeで`204` livenessと、同一account IDを保った次writer generationでの
   再起動を検証済み。WASM単体実行は同一`AssetId`の送金成功と異なる`AssetId`のeffectなし拒否を
   直接検証する。bounded query APIはDR-0082の設計のとおりstep 6で実装済み（implemented As-Is）。signed
   duplicate-transfer HTTP E2Eはstep 9（S0）で実装済み（implemented As-Is）。
6. DR-0082のbounded canonical query APIを、両方のstructured durable routerへadditiveに
   実装した（implemented As-Is）。`GET /v1/context`、`/v1/objects/{object_id}`、
   `/v1/receipts/{request_id}`、`/v1/senders/{sender}/next-nonce`だけを公開し、64文字の
   lowercase hex selector以外をstorage I/O前に拒否する。contextはtrusted chain/epoch、exact
   canonical `ProtocolConfig`、committed logical domainを返す。objectはabsence/tombstone/
   verified inline/blob referenceをtyped canonical resultで表し、inlineはnode-coreがhead、
   immutable version、digest、schema、provenance、owner projectionを照合してbody digestを再計算する。
   receiptはouter durable receiptとcanonical `NodeDedupRecord`のidentity/digest/re-encodingを照合し、
   nonceはcurrent trusted epochのpersisted `SenderNonceRecord`をnode-coreだけがdecodeして、true
   absenceなら0、deleted/corrupt stateならfail closedとする。sender pathはpublic lookup selectorで
   あって認可ではなく、submit authorizationは署名のみが与える。全successはcanonical type IDs
   `0xE102`-`0xE105`、`Cache-Control: no-store`、typed absenceを200で返し、既存のblocking
   admission、trusted fence/deadline/correlation identity、bounded object/receipt sizesを再利用する。
   scan/list/prefix/arbitrary state key、blob fetch、historical version selector、proof/indexerはMVP外。
   node-core側は`query_sender_next_nonce`/`query_object`/`query_request_receipt`を公開する
   （内部実装はprivate moduleに置き、crate rootからre-exportする。`node_core::query`は
   public moduleではない）。private `SenderNonceRecord`framingは外部へ漏らさない。`ObjectQueryResult`/
   `ReceiptQueryResult`はすべてのstatus（absence/tombstoneを含む）で要求されたexact selector
   （`object_id`/`request_id`）自体を型として保持し、HTTP層が別のlookupの結果を取り違えて
   bindできないようにする。`query_object`はinline/blobで分岐する前に version の
   creating-chain provenanceをtrusted chainと照合するため、cross-chainなblob recordも
   inlineと同様にfail closedする。blob referenceの`digest`/`blob_digest`はhead/versionで
   相互チェックされた値であり、fetchしていないbody自体をverifiedとは主張しない。
   native-http側は`0xE102`-`0xE105`の4つのcanonical codec（`HttpContextQueryResult`/
   `HttpObjectQueryResult`/`HttpReceiptQueryResult`/`HttpNextNonceQueryResult`）を追加し、
   すべてのresultに対応するselector（`object_id`/`request_id`/`sender`）を全statusへ持たせた。
   `CurrentInline`/`Present`のnested canonical bytes（`objects::Object`/`NodeDedupRecord`）は
   decode時にサイズ上限（`MAX_AUTHENTICATED_OBJECT_BODY_BYTES`/`MAX_DURABLE_RECEIPT_BYTES`）・
   decodability・outer selector/digestとのidentity一致・（receiptは）exact re-encodingまで
   strictに検証する。contextはzero id（protocol version/hash suite/profile/scheme/binding）・
   長すぎるchain id（`node_core::MAX_CHAIN_ID_BYTES`超過）・空のcanonical `ProtocolConfig` bytes
   を拒否する。4 route全て（`/v1/context`を含む）が共通helper経由で
   `DomainPlacementManifest::resolve_domain`を authenticated write pathと同じ
   activation-epoch-checkedな経路で呼び出し、`placement.domain()`を無条件には
   使わない。operational statusは、identity source unavailable・clock/runtime
   failure・durable readのwriter fenced/deadline/unavailable・durable schema
   generationがunsupported（`DurableReadError::SchemaMismatch`。persisted bytes
   自体のcorruptionではなくoperator/deployment側のschema世代不一致を証明する
   ものなので、corrupt-state側ではなくavailability側に分類する明示的な決定）・
   committed ProtocolConfigのinactivity/misconfigurationをopaque
   `503 query-unavailable`、corrupt/invalid persisted content・result encoding
   failure・identity source exhaustedをopaque `500 query-state-invalid`として
   区別する（capacity exhaustionは既存の`429`のまま）。
   `structured_durable_router`と`preinstalled_wasm_structured_durable_router`の両方へ
   GET routeとして配線した。stable literal vectors、round-trip/unknown-tag/selector-mismatch
   decoderテスト、4 routeすべてのboth-router parity（populatedなcurrent-inline
   objectとpresent receiptを含む。absenceのみに限定しない）、
   malformed-path-before-side-effectsテスト、
   object absent/tombstone/current-inline/current-blob/tamper/wrong-chainテスト、receipt
   absent/present/corruptテスト、nonce zero/advanced/deleted-corruptテスト、
   `/v1/context`と代表storage-backed object routeの
   inactive-placement-before-side-effectsテスト、503/500 operational
   classificationのcase tableテスト、
   admission/cancellationテストを両crateのtest suiteに追加済み。
7. DR-0083のMVP Rust client境界に従い、`crates/node-wire`へcanonical
   HTTP result codec・route/media-type contractを抽出し、`native-http`から同じpublic名を
   re-exportする。`clients/rust`は`node-core`と`node-wire`に依存して、seed-based
   Ed25519 key/address、canonical transaction build/sign、explicit request IDでのsubmit、
   bounded receipt wait、context/object/receipt/next-nonce queryを提供する。初期transportは
   strictなloopback-only synchronous HTTP/1.1とtest用traitだけに限定し、TLS、remote node、
   async、keystore、full `ProtocolConfig` decode、hash/certificate verification、blob fetch、
   asset固有helper、CLI policyはこのsliceへ含めない。serverとclientはshared stable vectorsと
   node-coreが受理するsigned transaction vectorでcanonical contractを固定した
   （implemented As-Is）。clientは全query selectorを応答内selectorと再照合し、transportは
   request framing injection、header/body超過、ambiguous length、transfer encoding、truncation、
   trailing bytes、close timeoutをfail closedにし、per-stage socket timeoutに加えて完全な1 requestの
   monotonic deadlineを適用する。receipt waitは同じoverall deadlineをtransportへ渡すためslow-dripで
   elapsed boundを更新できない。effects listはdeclared countとexact field countをallocation前に照合する。
   fake transportでsubmit/request bindingとbounded receipt wait、raw loopback TCPでadversarial response、
   実際にcomposeしたdevnet routerへの4 query全てのTCP E2Eを検証済み。live signed transfer/duplicate/
   restart E2Eはstep 9（S0）で実装した。
8. criterion 6の`apps/cli`を、実行時（non-dev）の直接依存が`clients/rust`のみのRust-only
   binaryとして実装した（`Cargo.toml`の`[dev-dependencies]`にはtest専用でreal devnetの
   composeとfixture構築、decoded execution-effects fixtureの構築、およびreal TLS E2E
   fixture構築のためだけの`execution`/`objects`/`runtime`/`native-http`/
   `sunrise-edge-devnet`/`tokio`/`rcgen`/`rustls`があるが、いずれもnon-test buildからは
   到達できない。implemented As-Is;
   ARCHITECTURE.md DR-0084）。Node/browser runtime、独自canonical codec、
   独自signing/RPC pathは導入していない。引数parsingはclap等を使わない小さな手書きの
   strict `--flag value` parserで、duplicate flag・unknown flag・flag値なし・宣言外の
   positional argumentをすべて拒否する。`address`（明示的に指定したdevelopment seed
   fileからAddressIsPublicKeyのaddressを導出）、`context`/`object`/`receipt`/`next-nonce`
   （`clients/rust`の対応するquery methodへの薄いwrapper）、`transfer`（explicitな
   destination ownerを要求するbounded devnet asset transfer）の6コマンドを提供する。
   `--tls-server-name`/
   `--tls-ca-cert-der-file`をいずれも指定しない場合、`--endpoint`はplaintext
   `LoopbackHttpTransport`の下でloopbackのみを受理する。S1実装後は、両方の
   TLSフラグを指定した場合のみ`--endpoint`を既に解決済みの`SocketAddr`として
   扱う`RemoteTlsHttpTransport`を使い、loopback制限は課さない。片方だけの指定は
   networkへ出る前にfail closedする（詳細はS1参照）。
   出力はdeterministicなline-oriented `key=value`テキスト、すべてのエラーはtypedな
   `CliError`でexit non-zeroとなる。development seed fileは明示的なpathのみを受理し
   （home directoryのdefault path無し）、symlinkと非regular fileを拒否し、Unix上では
   group/other permission bitを一切許可せず、内容は正確に64桁の16進数字＋任意の1個の
   trailing `\n`のみを受理する。seedはargvへ直接渡さず、標準出力へも一切printしない。
   `transfer`は`/v1/context`・sender自身の`/v1/senders/{sender}/next-nonce`・
   `--source-object`/`--destination-object`の`/v1/objects/{object_id}`結果を照会し、
   committed profileがEd25519 + AddressIsPublicKeyであること、contextとnext-nonceの
   epochが一致することを署名前に検証し、両objectがCurrentInlineであること、source ownerが
   signerであること、destination ownerが必須`--destination-owner` Addressと一致することを要求し、
   source→destinationの順でexactly two `Write` access manifestを構築し、
   `clients/rust`経由でtransactionをbuild・signし、caller指定のnon-zero request idで
   submitする。あらゆるassetは同一の`AssetId`/account/transfer pathを使い、native coinや
   feeの特別扱いは無い。cross-owner destination authorizationはDR-0086のtrusted
   preinstalled-module exact policyだけで可能であり、general owned-effects pathは
   sender-onlyのままである。literal ownership reassignment/giftingはfail closedである。
   `transfer`はsubmission自体もfail closedとして
   扱い、それはsubmissionに先立つqueryだけではない：submit resultの`responses()`が
   空である場合、いずれかのresponseが`NodeResponseStatus::Rejected`を宣言している場合、
   およびいずれかのresponseのpayloadがdecodeした結果`ExecutionStatus::Failure`である場合
   （node-coreレベルでacceptされたresponseであっても）は、それぞれtypedでnon-zero exitの
   `CliError`となる——このコマンドはrejectされたtransactionやfailしたtransactionを
   successとして報告することは無い。すべてのresponseのdiagnosticsはコマンドが終了する前に
   printされる（`responses()`を事前に検査するのではなく、iteration中に検出する）。
   そして、いずれかのresponseがこの意味でfailした場合、`--wait`には決して入らないため、
   `--wait`を同時に指定してもrejectされた・failしたsubmissionをapparent successへ
   変えることはできない。
   receiptのwaitは`--wait`で明示的に有効化した
   場合のみ行い、その際は`--wait-max-attempts`/`--wait-initial-backoff-ms`/
   `--wait-max-backoff-ms`/`--wait-max-elapsed-ms`をすべて明示的に指定する必要があり、
   隠れたdefault poll boundは無い（`--wait`無しでwait-bound flagだけを渡すのも拒否する）。
   `sunrise.devnet.asset_account.v1`のentrypoint名と`CanonicalStruct(0xF002,v1)`引数
   frameは`apps/cli`の`transfer`コマンドだけが知っており、`clients/rust`へdevnet固有の
   意味論は置いていない。そのために`clients/rust`へ追加した最小限のgeneric re-export
   （`abi::{AccessEntry,AccessManifest}`、`objects::{AccessMode,Object,ObjectError,
   Owner,decode_object}`、`execution::ObjectEffect`、
   `canonical_encoding::{CanonicalStruct,CanonicalEncodingError}`、`protocol_types`の
   基本型群、`current_inline_object_ref`ヘルパー、`ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID`
   定数、`ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`定数）はいずれもapplication固有の
   意味論を持たない。`objects::{ObjectError,Owner,decode_object}`と
   `execution::ObjectEffect`は、`transfer`がqueryしたobjectのcanonical bodyをdecodeし、
   client側でownerをdefense-in-depthとして検証し、decoded execution effectsから
   object effectをprintできるようにするためのものである。
   同時に`clients/rust`のtransaction構築をadditiveなsafe two-stage external-signer API
   （`transaction::PreparedTransaction::prepare`/`finalize`/`sign_and_finalize_with`）へ
   refactorし、`build_signed_transaction`は同じpathで実装することで既存のstable出力
   bytesを変更していない。`prepare`はexplicitなsender/active signature scheme/
   `TransactionRequest`からimmutableな値を構築し、実装済みでない
   signature schemeをframing前にfail closedで、専用の
   `ClientError::UnsupportedSignatureScheme(SignatureSchemeId)`で拒否する。この
   two-stage API以前は、`build_signed_transaction`は同じunsupported-scheme caseを
   より遅く・より曖昧に拒否していた：常に`SignatureSigner::sign_canonical`を呼んでおり、
   そのscheme一致guardが代わりにwrapされた
   `ClientError::Crypto(CryptoError::SignatureSchemeMismatch)`を返していた。
   `build_signed_transaction`のこのcaseにおけるcaller可視なerror typeは以前と異なるが、
   これはpurely additiveでmatchしやすくなったerror-typeの変更であり、protocolの変更ではない：
   同じcaseがframingや署名より前にrejectされる点、および成功する全caseのstable出力
   bytesが不変である点は変わらない。`signable_frame`はexternal
   signerが署名すべき正確なframed bytesを公開し、`finalize`は返された署名の長さが
   exact scheme長であることとAddressIsPublicKeyのsender公開鍵に対して暗号学的に
   verifyされることの両方を確認してからのみ出力を生成する（scheme不一致・不正な
   署名長・well-formedだが無効な署名・wrong signerの署名・transaction改ざんは
   すべてadversarial testでカバー済み）。ARCHITECTURE.md DR-0084が明記する通り、
   real Ledger（またはその他のexternal/hardware）署名はこのsliceでは実装しておらず、
   専用のSunrise Edge Ledger device app・APDU/host transport・on-deviceでの正確な
   signature frameのparsingとclear signing・public key/address照合・derivation path
   policy・device/app/version check・explicit user confirmation・host側signature
   verification・hardware-in-the-loop testが別途必要である。既存のSolanaやEthereum
   向けLedger appをSunriseのtransaction署名に転用することはできず、USB/HID/Ledgerへの
   依存はどのprotocol/client crateにも存在しない。
   **development-only residual: memory zeroizationは無い。** `load_dev_seed`の読み込み
   bufferとdecodeされた`[u8; 32]` seed、および`LocalSigner`のin-memory signing keyは、
   このsliceのどこにも`zeroize`-on-drop挙動を持たない通常のRust値であり、process
   memoryのdisclosure（core dump・swap・attachされたdebugger）によって、それらまたは
   allocatorがまだ上書きしていないcopyがresidentである間は回収され得る。これは
   `load_dev_seed`と`LocalSigner`が既存のdocumentationで明示している
   explicit・non-keystore・development-onlyという位置付け（production key handlingでは
   ない）と整合しており、暗黙の前提とせずここで明記する。
   parser/development seed file（symlink・permission・length。Unix）のadversarial
   test、`clients/rust`側の two-stage signing adversarial test（scheme不一致・不正な
   署名長・wrong signer・改ざん）、各query commandのfake `Transport` unit test、
   `transfer`のsuccess pathおよびepoch不一致・unsupported scheme・non-current-inline
   objectのadversarial test、実際にcomposeしたdevnet routerへのreal loopback TCP E2E
   （`context`/`next-nonce`/`object`の一括実行と、freshly seedしたaccount間での完全な
   signed `transfer`から`--wait`によるpresent receiptまでの2本）で検証済み。
9. **S0（restart/duplicate E2E、criterion 10）**を
   `apps/cli/tests/devnet_restart_duplicate_e2e.rs`として実装した（implemented As-Is）。
   real file-backed `SqliteDurableStore`、実際にcomposeしたdevnet router、real loopback
   TCP、user-facing transfer legとしての`sunrise-edge-cli::run`、独立検証としての
   `sunrise-edge-client`を使う。別々にconfigured/seededしたsender sourceからrecipient
   destinationへのamount 250のCLI transferをbounded waitで実行し、両accountのbalance変化と
   recipient ownerが前後で不変であること、decoded stateとreceipt/next-nonceを独立にcaptureした
   うえで、serverをgraceful HTTP
   shutdownでstopしserver taskをawaitし、`Arc<SqliteDurableStore>`をすべてdropしてSQLite
   fileを真にcloseしてから、`boot_local_store`で再openしてwriter generationがN+1へ
   進むことをassertし、reseedがExisting outcomeで同一account identityを返すことを検証し、
   新しいephemeral portでrouterをrecomposeする。restart後、balance/sequenceに加えて
   object query result・receipt result・complete next-nonce resultのcanonical bytesが
   restart直前とexactに一致することを検証する。`sunrise-edge-client`で直接構築した1つの
   signed `SubmitTransactionRequest`をsame boot内とrestart後の両方でbyte-identicalに
   再送信し、canonical response bytesが同一でeffectが二重適用されないことを証明する。already-committed
   なrequest idを別のtransactionへ再利用するとtypedでnonzeroなfail-closed HTTP conflict
   （409）になり、両object queryのcanonical bytes、CLI transferとraw transferの両receipt、
   sender nonceがすべて不変であることも検証する。さらに、reopen後のstoreへpre-restart
   writer generationのcontextで読み取りを試み、`WriterFenced`を返すことでold writer
   generationがfencedであることを直接証明する。これはorderly stop/reopenのみの証明であり、
   `kill -9`、power loss、torn write、load、concurrency、SQLiteのproduction適性は
   証明しない。

**Repository-boundary decision**（ARCHITECTURE.md DR-0081；DR-0080の同名決定のうち
repository-boundary/counter-demo deliverableのみを置き換える。DR-0080に記録された
実装済みのnative-http compositionやerror classificationはhistorical recordとして
変更しない）: CLI Developer MVP completion criteria 5-9のRust client library
（`clients/rust`）、Rust CLI（`apps/cli`）、TypeScript client library
（`clients/typescript`）、explorer app（`apps/explorer`）、wallet app（`apps/wallet`）は、
CLI Developer MVP Gateの実装期間を通じてこのmonorepo内に留め、実装時点でこれらのtop-level
ディレクトリとする。gate通過後も下記extraction条件を満たすまでは同様とする。pivot後、
criteria 7-9（`clients/typescript`/`apps/explorer`/
`apps/wallet`）のディレクトリ作成自体も
["CLI-First Node Production Gate"](#cli-first-node-production-gate)通過後まで実装着手を
deferする。`apps/cli`は`clients/rust`にのみ依存するRust-only client（Node/browser
runtimeには依存しない）。`apps/explorer`と`apps/wallet`は別々のSvelteKit + shadcn-svelte
（Luma）static/CSR app（request-time SSR、server adapter、`+page.server`/`+layout.server`/
`+server`、server actions/remote functions/server-held session・keyなし）とし、walletの
signing keyはbrowser限定とする。両app間で共有UI packageは、real duplicationが生じるまで
導入しない。旧DR-0080が定めた`clients/typescript`/`demo/counter`という組み合わせは
この6ディレクトリ構成に置き換わり、`demo/counter`は作成しない。別repoへのextractionは、
(a) canonical wire contracts/共有test vectorsが安定し、(b) 実際のindependent consumerまたは
独立したrelease cadenceが存在し、(c) E2Eがin-tree buildではなくreleaseされたdevnet
artifactをtargetできるようになるまで、`clients/*`のいずれについても延期する。

## CLI-First Node Production Gate

CLI Developer MVP Gate（criteria 1-6・10・11）を通過した後、TypeScript client・
explorer・wallet（criteria 7-9）へ進む前に、本物のnode自体をproduction-orientedへ
近づけるgateを課す。これはUIより先にnode/persistence/operationsを固める順序の
決定であり、新しいproduction criteriaを発明するものではない：以下はすべて既存の
criteriaを変更せず参照するだけである。

**参照する既存criteria（すべてunchanged）:**

- 後述の「Phase 15 To-Be production exit criteria」1-10（NodeEvent kind別のcanonical
  仕様固定、concrete dispatch実装、read-set revision assertionを持つversioned
  transaction、request/event-digest dedup、transactional outbox/indexed due-work
  claim、HTTP contract明文化、adapter policyとしてのretry/backpressure、TLS/認証/
  rate limiting等を含むproduction deployment検証、conformance/fuzz/load/soak/
  capacity budget、migration/backup/disaster recovery rehearsalとindependent
  security review）。
- 後述の「Post-MVP Production Hardening: Phase 15 persistence implementation order」
  1-6（durable domain adapter boundary、indexed due-outbox repository、
  structured durable transaction envelope上のnormalized PostgreSQL schema、
  write skew/object ABA/lease fencing等を含むshared conformance、real host/power
  fault・ENOSPC・connection exhaustion・snapshot restore・TLS commit-loss・
  PgBouncer rehearsalを含むreal fault/capacity/backup rehearsal、Cloudflare
  Durable ObjectとAWS persistenceでの同一contract実装とreal provider
  certification）。
- 後述の「Cross-phase production release gate」（Coding Requirements/Security
  Invariants充足、experimental/deferred/mock/temporary項目のcriteria未充足ゼロ、
  protocol specification/migration/disaster recovery/monitoring/capacity
  planning/key management/validator operationsの再現可能な文書化、supported
  runtime間でのcanonical bytes/digests/execution effects/commitments/consensus
  outcomes/proof verificationの一致、fuzz/property/adversarial/long-running test
  と第三者security auditの重大指摘解消、mainnet genesis前のrelease
  artifact/dependency/compiler/build provenance固定とreproducible build/upgrade
  rehearsal）。
- protocol version 3のFastCertificate/certificate publicationのatomic
  composition、`SubmitTransaction`以外の外部event familyのauthenticated/
  authorized ingress、S4/S5、および独立したsecurity/release gateが完了する
  までlive activationを禁止する既存のhard activation constraint（後述の
  「Phase 15 As-Is scope」参照）。fee（S3のbounded uniform ordinary-asset fee
  composition、DR-0087）とmodule/object effect（additive owned-effects
  entrypointおよびpreinstalled-WASM entrypoint）はimplemented As-Isだが、
  FastCertificate、certificate publication、他event familyのauthorized
  ingress、S4/S5、独立security/release gateは引き続き未実装の前提であり、この
  gate単独でprotocol version 3を有効化してよいことにはならない。
- `SubmitTransaction`以外の外部から受理されるnode-event family（特にcertificate、
  protocol upgrade、validator-set change）について、live activation前に
  `SubmitTransaction`と同等のauthenticated/authorized ingressを要求する既存の
  hard activation constraint（後述の「Phase 15 As-Is scope」参照。generic node-core
  handlerが`SubmitTransaction`をrejectすることは、これらの他のfamilyを
  unauthenticatedのまま受理してよいことを意味しない）。

**このgateを通過してもmainnetではない。** provider Phase 16（Cloudflare）・
Phase 17（Deno/Vercel/Supabase/AWS）のTo-Be production exit criteriaと、
独立したsecurity auditは、このgate通過後も引き続き必須である。

**ordered slices（S0-S5）:**

- **S0**: automated restart/duplicate E2Eと、それとは別の、local devnet/CLIの
  start・transfer・receipt・orderly restart・persisted stateをhandsで再現できる
  documented command列（implemented As-Is；criteria 10、
  `apps/cli/tests/devnet_restart_duplicate_e2e.rs`が
  raw byte-identical duplicate replayを証明し、README「Getting started」の
  local devnet/CLIコマンド列がそれとは独立にstart/transfer/receipt/orderly
  restart/persisted stateをhandsで再現する。documented commandはraw byte-identical
  duplicate replay自体を再現するものではない）。
- **S1**: remote TLS transportと、signing前のmandatory trusted protocol-context
  検証を実装する。この2つは別の懸念であり、混同しない：(a) remote TLS transportは
  明示的なtrust policy（例: システムCA + hostname検証、または明示的に設定した
  CA/anchorの検証）のもとでTLS server identityとhostnameを通常どおり検証する。
  brittleなleaf-certificate pinningを唯一の有効なTLS trust設計として要求しない。
  (b) TLS handshakeが成功しても、それだけではclientが意図したchain/protocolに
  接続していることは証明されない（TLSはtransport endpointを認証するのであって、
  protocol contextを認証するのではない）。したがってclient/CLIは、locally
  configuredなexpected chain identityとprotocol policyを要求し、signingの
  前に`/v1/context`から得たremote contextのchain id、protocol version、epoch
  policy、signature scheme、address binding、transaction auth profileをその
  期待値と比較して一致を要求する、という別のmandatory trusted protocol-context
  検証を実装する。TLS証明書/公開鍵のpinningだけでcross-chain signingを防げると
  主張しない。
  **実装状況（2026-09-01）：(a)(b)ともimplemented As-Is。S1全体として完了。**
  (b)のsigning前mandatory trusted protocol-context検証：`clients/rust`は公開
  `ExpectedProtocolContext`（chain_id、protocol_version、この初期sliceの
  exact-epoch policy、hash_suite_id、transaction_auth_profile_id、
  signature_scheme_id、address_binding_id、論理`AtomicityDomainId`）と、
  `/v1/context`を問い合わせてその8フィールド全てを検証してから結果を返す
  `Client::query_verified_context`、フィールド別の型付き
  `ProtocolContextMismatch`を持つ。`apps/cli`の`transfer`は
  `--expected-chain-id`/`--expected-protocol-version`/`--expected-epoch`/
  `--expected-hash-suite-id`/`--expected-domain`の5フラグを必須とし、
  missing/zero/malformedな値をnetwork dispatch前にrejectしてから
  `ExpectedProtocolContext`を構築し、以降のnext-nonce/object query、
  transaction構築、signing、submissionをすべてこの検証済みcontextに基づいて行う
  （未検証の`query_context`は使わない）。8フィールドそれぞれのmismatchに対する
  adversarial testが、`transfer`がcontext requestの1回だけで停止し
  nonce/object queryやsigningへ進まないことを証明する。

  (a)のremote TLS transport：`clients/rust`は`transport::RemoteTlsHttpTransport`
  を追加した。`LoopbackHttpTransport`と同一のbounded HTTP/1.1
  request/response framing・header/body上限・per-stage monotonic deadlineを
  共有しつつ、caller供給の`SocketAddr`（DNS解決は一切行わない）、caller供給の
  DNS server name（TLS SNIとpost-handshake hostname検証の両方に使う。空文字列
  やIPアドレスliteralは拒否し、接続先IPへのfallback検証も行わない）、caller供給の
  CA trust-anchor DER（新設の公開定数`transport::MAX_CA_CERTIFICATE_DER_BYTES`
  （16 KiB）で上限し、空・oversized・不正なX.509はrejectする。systemのtrust
  storeは一切参照せず、mTLS client証明書も提示しない）を要求する。
  `clients/rust/tests/remote_tls_transport.rs`はephemeralな`rcgen`発行の
  CA/leaf対と実際の`rustls` `ServerConnection`serverに対してreal client codeを
  駆動し（fake `Transport`は使わない）、正しいhostname/CAでの成功と正確な
  `Host`ヘッダ、誤ったhostname/CAでのTLS protocol error、stalled handshakeと
  handshake完了前のpeer closeがdeadline内に速やかに失敗すること、caller
  deadlineがtransport budgetを短縮すること、malformedなconstructor入力が
  network I/O前にrejectされることを証明する。同ファイルの回帰testは、
  shared bounded-stream refactorが`LoopbackHttpTransport`のplaintext framingを
  一切変えていないことも証明する。

  `apps/cli`の`context`/`object`/`receipt`/`next-nonce`/`transfer`各コマンドは
  対になったoptional flag `--tls-server-name`/`--tls-ca-cert-der-file`を
  受け付ける（`address`は networkへ出ないため対象外）。両方とも未指定なら
  従来どおりloopback-onlyのplaintext `LoopbackHttpTransport`を使い（非loopbackな
  `--endpoint`は引き続きreject）、両方とも指定した場合のみ`--endpoint`を
  既に解決済みの`SocketAddr`として扱い`RemoteTlsHttpTransport`を使う。どちらか
  一方だけの指定はnetwork dispatch前に型付きerror
  `CliError::PartialTlsConfiguration`でfail closedする。CA fileはstdのみで
  読み込み、transportと同じ`MAX_CA_CERTIFICATE_DER_BYTES`に1 byteを加えた位置で
  `Read::take`により読み取りを打ち切ってoversizeを検出することで無制限のbufferingを防ぎ、
  空/oversized/読み込み失敗をそれぞれ型付きCliErrorで報告する（証明書の中身は
  一切出力しない）。`apps/cli/tests/tls_cli_e2e.rs`は実際の`rcgen`/`rustls`
  loopback TLS serverに対して`sunrise_edge_cli::run`を直接駆動する2つの
  deterministic integration testを追加した：1つは`context`が正しいTLS
  authenticationの下で成功し、`Host`ヘッダが正確なDNS名+portであることを
  証明する。もう1つは、TLS自体は正しく認証できたserverが`--expected-chain-id`
  と食い違う`/v1/context`を返した場合、`transfer`がserver側の接続カウンタで
  確認できる形で正確に1回だけ`/v1/context`を要求し、nonce/object/sign/submitに
  進む前に型付き`ProtocolContextMismatch`を返すことを証明する——TLS
  endpoint認証とexpected-protocol-context検証が独立した別のboundaryであり、
  一方が他方を代替しないことを示す評価である。

  **明示する限界（silentに前提としない）：** DNS解決は一切行わない（callerが
  常に解決済み`SocketAddr`を渡す）。信頼するCAはcaller供給のDER 1個のみ
  （systemのtrust store、PEM/bundle形式、複数anchorの合成はいずれも未対応）。
  mTLSは未対応（client証明書を提示しない）。証明書のrevocation（CRL/OCSP）・
  rotation・lifecycle管理は未実装であり、CA証明書をoperatorのfilesystemへ
  どう配布・rotateするかのdeployment/operations evidenceも本sliceの範囲外
  （S5またはPost-MVP Production Hardeningのpersistence/operations workへ
  明示的に先送り）。TLS endpoint認証とmandatory trusted protocol-context検証は
  意図的に統合しない：TLS handshakeの成功がprotocol-context検証を代替すること
  はなく、検証済みcontextがTLS層の信頼範囲を広げることもない。これは
  mainnet readinessやproduction certificationの主張ではない：Phase 16/17の
  production exit criteriaと独立したsecurity auditは引き続き必須である。
- **S2**: **implemented and validated As-Is（2026-09-01、DR-0086）。**
  cross-owner transferをtrusted preinstalled-module pathのexact committed policyとして
  実装した。senderが所有するsigned access index 0は例外不可。non-senderの既存
  `Owner::Address` destinationは、exact module/version・`transfer` entrypoint・signed
  access index 1・`Write`・exact asset-account type hash/schema versionの場合だけ許可する。
  policyはreceipt/nonce reconciliation後かつobject I/O前にexactly once resolveし、同じ
  resolved moduleをauthorization/executionで再利用する。general owned-effects pathは
  sender-onlyのまま、source policy・`Consume`・wrong position/mode/type/schema/entrypoint/
  module・Shared/System/Immutableはfail closed。roadmapの「object owner変更」は異なる
  source/destination owner projectionを正しく扱い保存する意味であり、literal owner
  reassignment/giftingは実装せずfail closedのままdeferする。

  `SystemModule.semantics_hash`はopaque app semanticsとbounded policy集合を含むexact generic
  semantics envelope bytes（stable canonical type IDs `0xE007`/`0xE008`, v1）へcommitし、
  startup reconciliationとrequest resolutionがそれぞれactual bytesを独立検証する。
  S2 dev profileがinstallするasset moduleはversion 2で、`0xF011` semantics declarationも
  version 2とする。historical same-sender module/semantics version 1 bytesはstable vectorとして
  保持するが、このdev profileのregistry/catalogにはinstallしない。`0xF001` body・`0xF002`
  args・`0xF003` event schemaはversion 1のまま、WASM bytesも不変である。これはboundedな
  profile selectionであり、general module-upgrade activation architectureの完成を主張しない。
  established Transaction/ObjectEffect/Object/receipt/nonce/submit bytesは不変。devnet startupは
  per-owner balance/paired-sequence invariantを仮定せず、各current objectとversion-one history/
  receiptを厳密検証後、bounded configured-owner集合のfixed global seeded supplyをchecked検証する。
  CLIは必須`--destination-owner`をAddressとしてparseし、source=signer・destination=explicit
  expected ownerを署名前に検証する。real file-backed SQLite E2Eはcross-owner balance変化、
  recipient owner不変、same-boot/post-close-reopen exact replayのbyte-identical response/receiptと
  non-reapplication、changed signed requestによるrequest-id reuse 409時の両object canonical bytes・
  両receipt・sender nonce不変、writer-generation fencingを証明する。
  これはS2 As-Isのみでproduction/mainnet readinessではない。S3はDR-0087で後続実装済み。TypeScript client/
  explorer/walletとS4/S5は引き続きdeferredである。
- **S3**: **implemented and validated As-Is（2026-09-02、DR-0087）。** committed
  scheduleはbase=1、execution=`gas_used`単価=1、他category=0、fee registryは
  `DEVNET_ASSET_ID`を1:1で1つだけenableする。sourceのsender-owned `Write`をfee objectとし、
  distinct treasury ownerのordinary destinationをtrusted compositionがfinal `Write`として
  指定する。treasuryはWASM inputから除外され、successはapplication effectsとactual feeを
  atomic merge、trapはapplication effects/eventをdiscardしてnormalized full-gas fee-only
  source/treasury mutationをRejected receiptとcommitする。CLI fee flagsはall-or-noneで、
  real file-backed SQLite E2Eはexact fee=`1 + gas_used`、event pre-fee balance、trap charge、
  same-boot/orderly close-reopen replay non-reapplication、writer generation advance/fencing、
  request-id reuse conflict時のsource/destination/treasury canonical bytes・r1/r2/r3 receipts・
  nonce不変を証明する。single treasury serialization、insufficient-balance時のbounded
  execution-then-reject、fee distribution/production gas calibrationはdeferred。
- **S4**: secure signer（`LocalSigner`の development-only in-memory鍵に代わる
  production-oriented signing boundary）と、dedicated Sunrise Edge Ledger device
  applicationを使った実際のLedger統合（ARCHITECTURE.md DR-0084/DR-0088、
  `SIGNING.md`参照。既存のSolana/Ethereum Ledger appの転用はしない）。以下を順番に
  完了する。S4cまで通ってもAs-Is host integrationに過ぎず、S4dとCLI replacement前に
  S4完了とはしない。
  - **S4a: implemented and validated As-Is（2026-09-04、DR-0088）。** existing
    `0x2001` signature frameのstrict decoder、fixed 4 KiB hardware profile、
    `execution`/`wasmi`非依存のstrict Transaction v1 decode/re-encode、exact devnet
    transfer allowlist、signed bytes onlyのbounded ASCII display fixture、
    `PreparedTransaction` external-signer preflightを実装する。unknown module/version/
    digest algorithm/digest/entrypoint/args/access/fee shapeはtyped rejectionで、raw args/
    blind-signing fallbackはない。`request_id`、destination owner、transferred asset metadata、
    module nameはsigned contentとして表示しない。
  - **S4b: host-validated core implemented As-Is（2026-09-04、DR-0090）、device integrationはnext。**
    `SIGNING.md`が
    SLIP-0010 Ed25519 derivation、RFC 8032 compressed公開鍵への到達経路を2種
    （`ECPrivateKey::public_key`の生`04||X||Y`はapp側でY反転・sign bit変換が必要、
    `cx_edwards_compress_point_no_throw`の`pubkey[1..33]`は既にcompressed済みで
    再変換禁止）に区別した上でのdeterministic test vector要求（両経路実装時はagreement要求）、
    `get configuration`の6-byte success layout（`profile`は`1`に固定）、
    app SW/Ledger SDK・OS status（`6E03`/`5515`/`E000`/CLA `B0`）の分離、device-side
    sender比較と`6A80`、chain/protocol/epoch/fee assetのdevice policy pinをclarifyし、
    三access間のduplicate `ObjectId` rejectionを新たに要求し、DR-0088のsign transaction
    全体230-byte APDU capをFIRST最大255-byte（`total_length` 4 + path 21 + first chunk
    230）・first chunk最大230-byte（旧205-byteから訂正）へ訂正する（continuation chunkは
    230-byteのまま不変）。この訂正もSunrise canonical transaction/signature bytesや実装
    コードを変更しない。separate `sunriselayer/sunrise-edge-ledger-app` PR #1はexact E0 APDU
    state machine、independent canonical parse、exact devnet transfer policy、device-side sender
    pre-review checkを強制するderiver boundary、signed-fields-only review model、25 host tests、
    pinned CIをhost-validated `no_std` coreとして実装済みである。ただしこれはLedger SDK
    device binaryではなく、SLIP-0010 key derivation、Ed25519 signing、on-device address/transaction
    confirmation、APDU/USB/HID transport、Speculos fixture/UX、reproducible device build、physical
    device evidenceを一切追加しない。したがってS4b/S4は未完了で、actual dedicated Rust Ledger
    applicationとSpeculos evidenceが引き続きnextである。このrepositoryにnested appや
    workspace `exclude`は作らない。
  - **S4c:** this repositoryのseparate `clients/ledger` crateにhost APDU/USB transportを置き、
    CLIへall-or-none signer selection、device/app/firmware/profile/address検証を追加する。
    vendor dependencyはprotocol crate/`clients/rust`へ入れず、CLIのone-runtime-dependency
    invariantはDRで明示的に改訂する。
  - **S4d:** claimed device modelごとのphysical-device HIL、Speculos CI、user rejection/
    disconnect/reset/adversarial chunk evidence、pinned app/firmware compatibility matrix、
    reproducible device-app build hash、Ledger release/submission evidenceを揃え、CLIの
    dev-only `LocalSigner`をactual production pathで置き換える。Sunrise Edgeにはまだ
    registered BIP44/SLIP-0044 coin typeがなく、S4aのpathはdevnet-only provisionalである。
- **S5**: production persistence（PERSISTENCE.md/POSTGRES.mdのTo-Be）、
  transactional outbox運用、provider deployment（Cloudflare Durable Object/AWS）、
  operations（observability、runbook）、security（independent audit）、release
  evidence（migration/backup/disaster recovery rehearsal、reproducible build）を
  完成させる。

capacity/PITR/HAは、S5で明示的にtriggerされる（S5のcertificationやSLOが実際に
それらを要求する）までfrozenのままとする。これは既存の凍結方針
（`Post-MVP Production Hardening`冒頭の凍結宣言）を変更しない。

**production targetはconservativeにmulti-validator L1であり、single-operator
serviceではない。** このgateのS0-S5順序と既存のvalidator-set/consensus
criteriaは、単一operatorが恒久的に運用する前提のserviceではなく、複数
validatorが独立に運用するL1へ向けたstepとして設計されている。

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
  verified inputとdeterministic `ObjectEffect`をstrictに対応付け、owned Address objectのUpdate/Deleteを
  bounded durable mutationへ変換するadditive handlerはimplemented As-Isである。Create、owner/type/schema変更、
  version不整合、undeclared/duplicate effect、overflow、untrusted mutation contextはfail closedにする。
  verified objectはsigned manifestの宣言順でtransitionへ渡し、composition-trusted checkpointのregressionを拒否し、
  exact head assertion、Update/Delete、nonce、state、receipt、outboxを同じstructured durable invocationでcommitする。
  exact request replayはobject I/Oやtransitionより先にreceiptからreconcileするためeffectを再適用しない。
  generic handlerはresolved objectを渡さず、返されたeffectを黙って捨てずにfail closedにする。
  bounded preinstalled module loadとdeterministic WASM executionはadditive node-core entrypointへ
  接続済みで、認証時のcommitted registry、immutable catalogのcode/manifest/semantics commitment、
  manifest input boundとpre-activation gas ceilingをfail closedに照合し、code/manifest commitmentは
  digest自身のalgorithmと専用SystemModule domainで再検証し、canonical effectsをowned object atomic
  commitへ渡す。trap text/fuel accountingは固定reason/full-gas/empty-effectsへ正規化してから永続化する。
  exact replayはmodule resolve/object read/execution前にreceiptから返る。additive preinstalled-WASM native router
  （`preinstalled_wasm_structured_durable_router`/`_with_executor`）はこのentrypointへwiring済みである一方、
  generic structured durable routerはread-only entrypointのままである。Shared/System owner、blob body、
  arbitrary provider wiring、owned fast path certificateは未実装である。devnet/startup composition
  （`apps/devnet`）とfee debit（S3のuniform ordinary-asset fee slice、DR-0087）はimplemented As-Isである。
  node-core additive handlerはmanifest domainをI/O前にresolveし、typed receipt replayをstate readより先に行い、
  read-only assertionを含むstate/receipt/outboxをこのenvelopeへ構築する。definite commitまたはexact replay以外では
  outputを返さない。single-lock memoryとnormalized PostgreSQL conformance storeでatomic publication、object lifecycle/ABA、
  conflict rollback、read-only、bound domain、fence、deadline、object read-count bound、blob round-trip、replayを検証する
  （runtime/memory/PostgreSQL、node-core authenticated owned-object atomic effects、bounded preinstalled
  module execution、additive preinstalled-WASM native router wiring implemented As-Is; generic structured
  durable routerはread-onlyのまま、devnet/startup compositionとarbitrary provider wiring/certification
  pending）。
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
  fee（S3のuniform asset fee slice、DR-0087）とmodule/object effects（additive
  owned-effects entrypointおよびpreinstalled-WASM entrypoint）は現在implemented
  As-Isだが、FastCertificateとCLI-First Node Production GateのS4/S5・independent
  security reviewは引き続き未実装であり、protocol version 3のlive activationは
  禁止したままである。
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
  いない。protocol version 3のlive activationはshared-object ordering、
  FastVote/FastCertificate、certificate publication、他event familyの
  authorized ingressがprotocol semanticsの要求する箇所でauthenticated
  transactionとatomically composeされ、かつ独立してS4/S5と独立
  security/release gateが完了するまで禁止する。fee（S3のbounded uniform
  ordinary-asset fee composition、DR-0087）とmodule/object effect（additive
  owned-effects entrypointおよびpreinstalled-WASM entrypoint）はimplemented
  As-Isだが、単独ではこのconstraintを満たさない。
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
  retentionがない間はnew senderによるstate growthがeconomic meteringされない
  ——これはfee/object-effect compositionを持たないこのgeneric structured
  durable route（nonce-onlyの`SubmitTransaction` path）に限定した記述である。
  additive owned-effects entrypointとpreinstalled-WASM entrypointは別途fee
  （S3のbounded uniform ordinary-asset fee composition、DR-0087）とmodule/
  object effectsをimplemented As-Isであり、本項の対象外である。このgeneric
  As-Is routeをlive transaction ingressとして公開してはならない。
  FastCertificateおよび他event
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
  （implemented As-Is）。optional shared commit-loss capabilityはbounded test-only `NoTls` TCP proxyと、
  PostgreSQL `SSLRequest`を必須化してephemeral private CA・`localhost` SANをrustlsで検証する別の
  bounded TLS-terminating proxyを介し、
  plain state commitへCOMMIT dispatch直前のconnection lossを1回注入してstate ground truthが存在しないことを
  証明し、別途structured invocation commit・outbox claim・acknowledgementの3箇所へbackend COMMIT acceptance
  直後のconnection lossを注入して、いずれもIndeterminate(ConnectionLost)として分類されつつ、invocation commitでは
  exact state/receipt ground truthとRequestAlreadyCommittedを証明する。same-lease claim replayや
  same-identity ack replay単独ではpersistedとuncommittedを区別できないため、claimでは別leaseでのclaim probe
  （元leaseがまだactiveであることをNoDueWorkで証明）、ackでは元leaseでのreclaim probe（LeaseIdReuseとして
  rejectされることを証明）を先に行った上でsame-identity reconciliationを証明し、最後にconnection pool
  recoveryを検証する。TLS版はIP-host negative connection rejectionとcompleted authenticated handshakeも
  証明してexact same shared casesを実行する（implemented As-Is；ARCHITECTURE.md DR-0074）。ただしTLSは
  test proxyで終端してbackend PostgreSQL legはplaintextであり、client/driver-to-test-terminatorの証跡に
  限る。backendがCOMMITへ成功応答を返したことの証跡であり、abrupt process/power lossに対するcrash
  durability、PostgreSQL-server/provider TLS、mTLS、certificate rotation/revocationの証明ではない。
  別途、serializedなlive testがcommitted structured invocation（state、exact receipt、
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
  resource exhaustion、load/soak capacity、production certificationは未実装のままである
  （provider-managed poolerの挙動はDR-0075のbounded rehearsalとして下記の通り一部implemented
  As-Isだが、production certification/load/failoverは引き続き未実装）。別のrequired live testは
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
  さらに別のrequired live testはdigest-pinned PostgreSQL 18.6とdigest-pinned
  `ghcr.io/icoretech/pgbouncer-docker` 1.25.2を1つのisolatedかつ生成済みDocker bridge
  networkへ起動し、PgBouncerはnetwork alias経由でのみPostgreSQLを解決する（host-published
  addressは使わない）。このtest自身のdirect verification connectionはproxyを経由せず
  PostgreSQL自身の別のpublished portへ直接張るため、proxyの単一backendが意図的にblockされて
  いる間も使い続けられる。`pgbouncer.ini`/`userlist.txt`はcontainerへ`docker exec ... dd
  of=<path> status=none`のstdin経由で書き込み、shellもhost bind mountも使わない。`tee`とは
  異なりBusyBox `dd`は`status=none`指定時にtarget file以外へ何も出力しないため、書き込んだ
  credential/configがcaptured outputへechoされることもない。credentialはgenerated passwordであり、
  `password_encryption=md5`を設定したPostgreSQL自身の`pg_authid.rolpassword`を読み戻して
  userlistのMD5 credential hashとしてそのまま使う（testが自前で計算しない）。設定は
  `pool_mode = transaction`、対象database/user poolに対して`pool_size`/`default_pool_size`/
  `max_db_connections`/`max_user_connections = 1`、nonzeroな`max_prepared_statements`、
  boundedな`query_wait_timeout`であり、いずれもPgBouncer自身のadmin console
  （`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/`SHOW CLIENTS`、
  simple query protocol経由）で直接証明し、client側の挙動から推測しない。`SHOW CONFIG`の
  `default_pool_size`/`max_db_connections`/`max_user_connections`と、対象databaseの
  `SHOW DATABASES`自身の`pool_size`もそれぞれ独立に読み戻してexactly oneであることを証明する
  （rendered `pool_size`だけから推測しない）。同時にopenな2つのdistinct client connectionが
  それぞれ1回のtransactionを順に実行し、`SHOW SERVERS`の`remote_pid`が両方で同一であることから
  transaction poolingが実際に同一のPostgreSQL backendを再利用したことを証明する。実際のadapter
  （genuineな`r2d2` poolと`PostgresDurableStore`、専用の`application_name`で識別）をproxy経由に
  向け、別のdirect proxied clientがCOMMIT/ROLLBACKを送らずtransactionを開いたままpoolの唯一の
  backendを保持している間（`SHOW SERVERS`の唯一の行がPgBouncer自身の`active` stateであることを
  証明し、単に存在するだけでないことを示す）に、PgBouncer自身の`query_wait_timeout`より十分長いcontext deadlineで
  1回のadapter structured invocationを実行する。live evidenceとして、PgBouncerのqueue
  timeoutはPostgreSQL protocol SQLSTATE `08P01`（`query_wait_timeout`）としてadapterの最初の
  文（transaction開始の`BEGIN`）に現れ、このcrateの`PreCommitFailure::from_sqlstate`には専用の
  分類がないためdefaultの`Unavailable`扱いとなり、definite pre-commit
  `Rejected(UnavailableBeforeCommit)`として観測される（`Indeterminate`ではない）。観測された
  経過時間はPgBouncer自身の`query_wait_timeout`を基準に上下からboundし、このtestの持つより大きな
  context budgetではなくproxy自身のqueue timeoutに起因することを証明する。state/receipt/outbox行の
  非公開はproxyを経由しないdirect operator connectionを通じて証明する。blocking transactionを
  解放した後、同じadapter pool/storeで同一invocationを再試行する。この再試行はexplicitに
  文書化されたひとつの既知のtransientのみを許容する ——
  `r2d2`はblocked probeのconnectionをevictする代わりrecycleすることがあり得る（local
  `is_closed()`がPgBouncerのasynchronousなsocket closeにまだ追随していない場合）ため、次の
  checkoutがすでに死んでいるそのconnectionを受け取りsub-millisecondでlocalかつunclassifiedな
  I/O errorとして失敗することがある（timingの点でgenuineなproxy rejectionとは明確に区別できる）。
  このretryはその狭い形状だけを許容し、loopの最終結果は必ず`Committed`でなければならない
  （accumulatorは`Committed`ではなくrejectionで初期化されており、将来retry回数を0へ縮める編集が
  あってもvacuousにpassせず確実にfailする）。
  recoveryは`Committed`を証明し、同じ`remote_pid`証跡を再度呼び出して、recovered commitが
  2つのsynthetic clientで観測したのと同一のsole backendによって処理されたことを証明した上で、
  `SHOW CLIENTS`をadapter poolの`application_name`で絞り込むことで
  adapter pool自身のproxy connectionが解放されたbackendを奪ったことを証明し、同一invocationの
  replayはexact `RequestAlreadyCommitted`を返し、exact outbox messageはclaim/ackを経て
  `NoDueWork`となり、poolはさらなるreadにも使い続けられる（bounded local PgBouncer
  transaction-pooling rehearsal evidenceのみimplemented As-Is; ARCHITECTURE.md DR-0075）。これは
  provider-managed pooler service certification、load/soak capacity、PgBouncerのhigh
  availability/connection draining、client/backendいずれのlegのTLS、real writer failover、
  production readinessの証明ではない。
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

Post-MVP Production Hardening: Phase 15 persistence implementation order（To-Beからの逆算）:

以下はCLI Developer MVP Gate通過まで凍結していた。ただし、MVPのatomic correctness、
restart safety、fail-closed behaviorを直接満たすために必要な既存contract修正は先行して
よいものとしていた。CLI Developer MVP Gateは現在通過済みであり、以下の項目は
["CLI-First Node Production Gate"](#cli-first-node-production-gate)のS5が参照する
production persistence作業そのものである。S3は実装・検証済み（DR-0087）、S4aは
hardware-signing profile/host preflightとして実装・検証済み（DR-0088）である。
DR-0089はS4b device contractをdocument上でclarifyし、DR-0088のAPDU 230-byte capを
FIRST最大255-byte・first chunk最大230-byteへ訂正しただけでdevice app・Speculos
evidenceを追加していない。DR-0090により、merge済みseparate `sunrise-edge-ledger-app`
repositoryのPR #1はhost-validated `no_std` coreをAs-Isで提供するのみで、Ledger SDK
device app・実際のSLIP-0010 derivation/signing・on-device UI・APDU/USB/HID transport・
Speculos・reproducible device build・physical evidenceはまだ存在しない。S4b/S4は
引き続きincompleteであり、現在のimplementation priorityはactual device
integration/Speculosである。TypeScript client/explorer/walletとS5は引き続き既存の
順序でdeferredであり、S5は順序を飛ばさず後続する。
capacity/PITR/HA等のS5 certification項目はS5または明示的なSLOがtriggerするまで
引き続き凍結する。

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
   schema/version skewを追加する。optional shared commit-loss capabilityはbounded test-only `NoTls` TCP proxyと
   strict CA/hostname verification付きのbounded TLS-terminating proxyを介し、
   plain state commitへのCOMMIT dispatch直前connection lossとinvocation commit・outbox claim・acknowledgementへの
   backend COMMIT acceptance直後connection lossを別々に注入し、いずれもIndeterminate(ConnectionLost)として
   分類されることと、前者はstate ground truth不在、後者はexact state/receipt ground truth・RequestAlreadyCommitted
   （invocation commit）を証明する。claim/ackはsame-lease/same-identity replay単独では非committedと区別できない
   ため、別lease claim probe（NoDueWork）とoriginal lease reclaim probe（LeaseIdReuse）で先にpersistedを証明した上で
   same-identity reconciliationを証明し、pool recoveryを証明する
   TLS版ではIP-host negative rejectionとauthenticated handshake countも証明する
   （memory/PostgreSQL/commit-loss capability implemented As-Is；ARCHITECTURE.md DR-0074；backendの
   成功応答とclient/driver-to-test-terminator TLS lossの証跡でありabrupt process/power lossに対する
   crash durability、PostgreSQL-server/provider TLS・mTLS・certificate lifecycleの証明ではない;
   provider adapters、other fault/capacity certification pending）。別途、serializedなlive testがcommitted structured
   invocationの直後にdatabase-service containerを`docker kill --signal=KILL`し、restart/readiness/
   fresh connection reconciliationを検証する（implemented As-Is; ARCHITECTURE.md DR-0069）。これは
   database-process SIGKILLとWAL recoveryの証明のみであり、abrupt host/power loss、storage write-cache
   flush/torn-write/media/filesystem fault、PostgreSQL-server/provider TLS、capacity/load/soak、real writer
   failover、backup/restore、provider certificationは未実装である。
5. real host/power fault（storage write-cache flush、torn-write、media/filesystem fault含む）、
   commit-boundary/real storage-device ENOSPC、
   capacity/load/soak、backup/restore、writer failoverをrehearsalする。database-process
   SIGKILL/WAL recovery、bounded pre-commit data-tablespace ENOSPC（DR-0070）、bounded pre-commit
   WAL-filesystem ENOSPC（DR-0071）、bounded server connection-slot exhaustion（DR-0072）、bounded
   `pg_dump`ベースのdatabase-snapshot restore rehearsal（DR-0073）、bounded
   client/driver-to-test-terminator TLS commit-loss evidence（DR-0074）、bounded local PgBouncer
   transaction-pooling rehearsal（DR-0075）以外は
   このstep 5の全項目が未実装のまま残っている。connection exhaustionはDR-0072でserverが飽和した
   際にadapter poolがdefinite pre-commit `Rejected(DeadlineExceededBeforeCommit)`を返すことを
   bounded disposable containerで証明したが、real-device resource exhaustion、load/soak capacity、
   production certificationは未実装のままである。DR-0075は digest-pinned PostgreSQL 18.6と
   digest-pinned `ghcr.io/icoretech/pgbouncer-docker` 1.25.2をisolatedなDocker networkへ起動し、
   PgBouncer admin console evidence（`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/
   `SHOW CLIENTS`）でconfigured transaction modeと、default_pool_size/max_db_connections/
   max_user_connections/tested databaseのSHOW DATABASES pool_sizeが厳密に1であることと、
   2つのsimultaneously openなclient connectionが同一backendを
   sequential transactionで再利用することを直接証明し、real adapterをproxy経由に向けた上で、
   direct proxied clientがproxyの唯一のbackendを`active` stateのtransaction中に保持している間、adapter
   invocationがPgBouncer自身の`query_wait_timeout`満了によりdefinite pre-commit
   `Rejected(UnavailableBeforeCommit)`となることと非公開を証明し、release後は同一invocationの
   commit（recovered commitが同一sole backend PIDで処理されたことを再度証明）、
   `RequestAlreadyCommitted` replay、exact outbox claim/ack、pool usabilityを証明した
   （bounded local PgBouncer transaction-pooling rehearsal evidenceのみimplemented As-Is;
   ARCHITECTURE.md DR-0075）。これはprovider-managed pooler service certification、load/soak
   capacity、PgBouncerのhigh availability、TLS、real writer failover、production readinessの
   証明ではない。DR-0073は
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
