# SUDP 修订：签名的、可授权的多写者状态（+ 身份层实例化 + 代码规格）

> **状态**：设计已收敛（2026-07-30 夜，一整轮第一性原理讨论）。本文扎在**真实代码/协议现状**上（sudp crate 0.2.1 本地 = crates.io 字节一致；protocol.md / sync.md / identity-uik-aik.md 已勘察）。
> **用途**：① SUDP 协议修订 + 论文调整（20 天内投安全会）；② SUDP 代码修改规格（**没时间充分测试**，故规格要清楚到能低风险动手）。
> **分层决定（勘察真论文后细化，待用户拍）**：现有 SUDP 论文（`safeclaw-paper/`，题《SUDP: Secret-Use Delegation Protocol for Agentic Systems》）是**完整已证的单用户**贡献 = **第一篇（20 天，建议基本不动）**。我们这一夜的**多写者 + 身份 + 团队 + 签名状态**是**大扩展 = 第二篇**（A1 抽象层 + A2 实例化层）。**建议 20 天别把扩展硬塞进第一篇**（风险，见 §A3 ⭐）。术语三边统一（见「术语」节）。代码改动（§B）为产品服务，与论文在哪写**解耦**。
>
> **⚠ SUDP core ↔ 扩展的边界（用户校准，重要）**：**SUDP core 只知道「K + 一把包 K 的 wrapping key + 抽象 authenticator + grant/redeem」——不知道 UIK、不知道 `custody→UIK→K` 三层、不知道角色/状态签名。** 尤其：**`passkey→UIK→K` 三层不是 SUDP 概念**——SUDP 只看到「一把 wrapping key 包 K」，这把 wrapping key 是直接来自 passkey PRF（今天）还是经 UIK（扩展），SUDP **不关心、看不见**。⇒ **A1（principal/签名/角色）+ A2（UIK / custody→UIK→K / team）全部是扩展、建在 SUDP core 之上；SUDP core 不动。** 我早先说「SUDP 拿抽象的槽」是**说过头了**，已按此校正：抽象的 principal/签名/角色是**扩展的抽象层（A1）**，不是 SUDP core。
> **iron rule 遵守**：protocol abstract 要纯（SUDP 不点名 UIK/passkey）；不 overclaim；改论文前对齐真实文本。

---

## 0. 现状基线（grounded，别凭记忆）

SUDP 今天是一套**全对称**的、cloud-blind、server-authoritative、per-item 的密封状态同步：

- **密钥链（全对称）**：`y_c(passkey PRF 输出) → W_c = HKDF(y_c; salt=prf_salt; info=DS_WRAP‖cid‖ver) → K̂_c = Wrap_{W_c}(K) → K 密封 M`。（protocol.md §2.2；`primitives/kdf.rs:52`、`primitives/wrap.rs`。）
- **K**：每 vault 一把，**永不在活 id 下轮换**（sync.md §1 铁律，防「daemon 持 K 打不开 blob」的分叉）；delete+recreate 换新 id。`ver: u16`。
- **SealedState** = `{version, registry(cid→WebAuthn pubkey), credentials[], ciphertext}`；明文视图 **M = ProtectedState** = `{secrets, authenticators(cid→W_c), aux(不透明 JSON)}`。SafeClaw 的 vault 模型全塞在 `aux` 里。（`state/sealed.rs`、`state/protected.rs`。）
- **AEAD** = XChaCha20-Poly1305（24B nonce、16B tag）；body 封装 AAD = `DS_SEAL‖ver_be`（nonce 前置**不进 AAD**）。
- **per-item v3（已建/cutover 中）**：`item_id = HMAC(K_id, lp(ns)‖lp(name))`，`K_id=HKDF(K,…,"safeclaw/item-id/v1")`；`seal_record` 的 AAD = `suite‖lp(DS_ITEM)‖lp(domain)‖lp(vault)‖lp(id)‖lp(version)`（**version 已绑进 AAD**，但 crate 明说 AAD 不防回滚，回滚由 caller 单调版本管）。**`ItemPayload={ns,name,status,body}` 整个在密文里**（云连 tombstone 都分不出）；只有单向 HMAC 的 `item_id` 明文。（`storage/item.rs`、`state/record.rs`。）
- **wire 明文字段**：whole-blob `{vid, version(云盖章、单调), status, blob}`；per-item `vault_items{item_id, version(写者定、CAS 单调), seq(云游标), ct}`、`vault_keys{cid, data=keyset}`（**keyset 云可见 by design**，它是给你 K 的东西、不被 K 密封；`data` 里已含 `x25519_pub`）。

**今天没有的（勘察确认，NOT PRESENT）**：
- **非对称身份密钥**——0。存在的非对称都是**传输/授权/投递**用（WebAuthn ECDSA 验 β、HPKE X25519 外层信封、ECDH KEM 导出、跨设备 deposit 的 x25519_pub），**没有一个是持久的状态签名身份**。
- **状态/config/item 的签名**——0。唯一签名 = passkey 对 `β = H(DS_BIND‖r‖H(o))` 的 WebAuthn assertion，是**每操作的授权证明**，签的是 β、不是状态。（`passkey/webauthn.rs`、`beta.rs`。）
- **明文 type**——0（ns/name/status 都在密文里）。
- **`generation` 纪元**——0（sync.md §9 DP-S1 里推迟，代码零出现）。
- **角色/授权身份**——0（`members`/`agent` 只是 `ItemNs` 变体名 + 注释；UIK/AIK 在 `design/identity-uik-aik.md` 里是「proposal，nothing implemented」）。

**⇒ 修订的起点很干净：全对称 + passkey-β-授权 + HPKE/ECDH 传输，零状态签名、零身份、零角色。我们要加的是纯新增,不是重写。**

---

## 术语（三边统一：论文 = 协议 = 代码；用领域标准词，不自造）

安全/访问控制文献的标准分层，**不是一个抽象，是三个不同层**（Lampson/Abadi/Burrows/Wobber《Authentication in Distributed Systems》即以 principal + "speaks for" 立论；标准模型：authentication 定 principal，authorization 决定放行）：
- **principal** = 身份实体（谁）。第二篇实例化为 **UIK / AIK**。
- **authenticator** = 认证 principal 的凭据/机制（怎么证明是他）。实例化为 **passkey**（custody 的一种）。今天 SUDP 已用此词（WebAuthn 亦然），标准。
- **authorization** = 决定放不放行 = 本文的 **role × type**。
- 标准句式（三边都这么说）：**an authenticator authenticates a principal; a principal（带 role）被 authorize 去写某个 type**。
- **不合并**：passkey 不是身份（叫 principal 会混），UIK 不做认证（叫 authenticator 是反的）。留两个词=标准分层,非冗余。引用见 Lampson 系列。

## A1. SUDP 扩展：可验证多写者签名状态 + 角色授权（抽象层，归**第二篇**；不点名 UIK/passkey）

把 SUDP 从「密封的多写者同步」升级成「**签名的、可授权的、可被任何人验证的多写者状态**」。全部用抽象词（principal / custody / role），**不出现** UIK、passkey、owner、member、team。

**A1.1 Principal（抽象身份）**
引入抽象 **principal**：一个拥有**非对称签名 keypair** 的写者。它的**公钥即其标识**（id = 公钥或其哈希）。私钥的 **custody 是抽象、可插拔**的（SUDP 不关心是 authenticator、password 还是 HSM）。
—— **别把 principal 当成「一种 authenticator」**（会把 custody 和身份重新混起来）：
  - **Authenticator（如 passkey）= custody + 每操作授权**：(a) 提供 PRF 去**包住 principal 私钥**（custody），(b) 对 **β** 签名授权一次**在线操作**（手势绑定、临时、绑设备）。这是今天 SUDP 已有的腿。
  - **Principal（如 UIK）= 持久身份，签状态**：私钥被 authenticator 的 PRF 包住；它对 **record** 签名（作者身份、本会话内、无手势、跨设备、一人一个）。这是本次**新增**的腿。
  - 分水岭：**β 必须手势绑定**（一次操作要一个人在场点头）→ 只能 authenticator；**状态签名要 daemon 无手势地随时签** → 只能 principal。**两把钥匙、两个用途、两层**——principal 是 authenticator 的**兄弟，不是子类**。
- **principal 可轮换（rotation hook，抽象层就留口）**：SUDP 的 principal 抽象支持**带签名的 succession**（旧 principal 签新 principal 过继、id 连续）；身份层（A2）用 lineage 实现。这让「UIK 轮换/更新」天生可扩展、不用回头改 SUDP。

**A1.2 签名的状态写入（核心新增）**
每条密封 record 附带一个 **principal 对该 record 规范绑定的签名**，绑定内容 = `(type ‖ item_id ‖ version ‖ vault ‖ H(sealed_body) ‖ principal_id)`，用 SUDP 已有的**长度前缀 + 域分隔**构造（照抄 `record_aad` 的形状，新增域标签如 `DS_SIG = sudp/v1/item-sig`）。
- 一个签名**干三件事**：授权（见 A1.4）、完整性/作者身份、防回滚（version 在被签内容里 + caller 单调）。
- **tombstone 也签**（删除是一种 record 状态，签名者+type 决定谁能删）。

**A1.3 明文 type（一份，签名背书，不存两份）**
把 record 的 **type（小枚举）暴露成明文**;**name 与 body 仍密封**。type↔密封内容的绑定**由 A1.2 的签名保证**——所以**密文里不再存第二份 type，也不需要 daemon 去 cross-check**（这条是本轮一个关键收敛：一份明文 type，签名认证它，消灭「两份不一致」的攻击面）。`status(live/tombstone)` 同样提升为明文 + 被签(让 server 能按 type/status gate、区分删除)。
- **daemon 只信「解密后 + 验签通过」的 type**;server 只用明文 type 做写门(见 A1.5)。

**A1.4 授权 = role × type 判定(可插拔钩子)**
SUDP 定义一个**抽象谓词** `authorize(principal_role, record_type) → may_write`。SUDP 只提供**钩子 + 强制点**(写入时校验签名者 role 对 record type 是否放行);**具体策略是外部输入**,不写进协议。
- 未知 type / 缺失 role → **fail-closed**(默认拒)。

**A1.5 验签放哪(信任墙在读者侧)**
- **server 可验**(稳定性:坏写门口就拒,不打回滚战);但 server 会被黑,**不是安全保证**。
- **每个读者(daemon)必须逐条验**(签名 + role×type):这是真正的墙,后端伪造/直连库写都被读者拒。原则 1+3。

**A1.6 验签失败的处理(状态机)**
坏签名 → **拒这条、守上一份验过的好版本、只隔离这条、大声报警**;**绝不删本地**(只 A1.7 的签名 tombstone 删)、**绝不整体崩**(per-item 隔离)、安全攸关 type 无好版本兜底则**退最严默认(deny)**。签名把「回滚战」变成「原地不动」(坏写从未被采纳)。

**A1.7 签名的 re-key 纪元(泛化 DP-S1,in-place 换 K)**
引入 envelope 的 **`generation` 纪元 + 一条被签的 re-key 事件**:principal(具授权角色)签一次「vault 换到 K'@generation N+1」;读者见**更高的、签名有效的** generation → 丢旧 K → 用新封装的 K' 重解锁。
- 这让「K 可在活 id 下 in-place 轮换」**而不破坏 sync.md 的「一 K 一活 id」不变量**——因为 generation 是**带签名的显式信号**,不产生「无信号的 K 分叉」(sync.md §2/§9 早留了这个口,只是推迟)。
- **⚠ generation 递增必须被授权角色签名**(对抗检查逼出):否则恶意后端狂发假 generation → 每个 daemon 反复丢 K 要求重解锁 = passkey 风暴 DoS。

**A1.8 不变的(别过度改)**
cloud-blind、terminal-state 同步(非 oplog)、per-item 密封、tombstone、CAS/单调 version、retain-K-while-unlocked、`item_id=HMAC(K_id,ns‖name)` 的盲化寻址(name 仍盲)。

---

## A2. 身份 + 团队实例化（**第二篇**的具体层；往 A1 的槽里塞具体）

- **principal = UIK/AIK**:UIK=人的身份 keypair(Ed25519,按 `identity-uik-aik.md`),AIK=agent 的;id = pubkey 哈希(自证)。人写=UIK 签(passkey 解锁后本会话可签),自动写(OAuth 刷新)=设备/AIK 签(无需人在场)。
- **custody 实例**:passkey PRF / master password KDF / HSM,都只**包住 UIK 私钥**。**三层拉直**:`custody → UIK → K`(K 用 **HPKE 封给成员 UIK 公钥**,复用现成云可见 keyset + 每凭据 x25519 地基);**撤掉今天 W_c 直接包 K 那条**(推翻 §51 的 passkey∥UIK 并列,改分层——见团队安全模型文档)。加设备=只给 UIK 加一份 custody 包,**不碰 K**。
- **role×type 策略(v1 最小)**:member 可写 `{secret, connection, connecting}`;其余(policy/stores/store_order/audit_retention/services + 未来未知 type)**owner-only**;**keyset 操作在端点层 owner-only**(删别人的 wrap=owner)。可扩展:加 Manager/view-only = 往策略表加行,SUDP 不动。
- **config 完整性**:owner-only 的 type 由 owner 的 UIK 签名(A1.2 的实例),读者验签不过就退上一份/最严默认——**「只有 owner 签过的才算数」**;server 的写门只是稳定性,不是完整性来源。
- **team 全景**(细节见 `team-shared-vault-security-model.md`):成员=谁有 keyset wrap;sharedness=**服务器权威、随 sync 下发的 envelope bit**(不再数 members);踢人五机制(切/re-key/轮换上游/租约/被移出即清);forward-secret re-key = A1.7 的签名 generation。
- **密钥生成**:UIK **客户端生成**,云只握「公钥 + custody 包的私钥密文」。**主线现状 = 浏览器仪式里生成**(勘察确认 onboarding 是 web-first、后端硬焊「先在网页封 vault」),故 UIK 顺手在同一场 `setupEnvVault` 浏览器仪式里多铸一把 = **零重排、零新可见步骤**;服务端投毒风险=接受的保底。**daemon-gen 为未来硬化**(Path B `sc vault create` 已证原生 keygen 可行,但对主线是一次真正的 onboarding 重排,晚做)。
- **UIK 轮换/更新(用户点名确认扩展性,机制现在不定)**:身份层带 **lineage**——旧 UIK 签过继证书给新 UIK、**id 连续**(旧签名在 lineage 下仍有效),之后新 UIK 接手。**可由 daemon 驱动**(原生生成新 UIK,比浏览器强,接上 daemon-gen 硬化线)。**私钥真泄露的恢复**要额外一个「撤销/恢复权威」(旧钥攻击者也能签→需更高权威裁定),具体机制未来再定。**扩展性已在**:靠 A1.1 的「principal 可轮换 / 带签名 succession」钩子,SUDP 不用改。

---

## A3. 论文该怎么调（对着**真论文** `safeclaw-paper/`，诚实，不 overclaim）

**先纠一个我早先的错**：我说过「必修 SCSV 死格式坑」——**那是 protocol.md §5.1 的问题，不是论文的**。真论文把格式写得**抽象**（AEAD=AES-GCM/ChaCha20-Poly1305；AAD=`DS_*‖ver`；label 是 profile 参数），**没有 SCSV、没有过时 label、和活 crate 一致**。⇒ **论文格式无需改；只 protocol.md §5.1 要清**（见 §D）。

**真论文现状（已勘察）**：单用户、多凭据（**any-of-N，可互换**）；三角色 U(authorizer)/R(requester=agent，不可信)/T(custodian，restricted trust)；7 性质 AV/OB/UB/CRC(核心)+CSB/CMC(out-of-scope)/RFS；Theorem 1 + 5 命题（**证明是 sketch，非机器验**）；A1–A9 假设。**无角色/成员/团队、无多写者、无 per-write 作者身份**。它是**完整、已证的单用户贡献**。

**术语好消息**：论文 §10 future-work 原话「authenticator primitives suited to **non-human principals**, enabling agent-rooted authorization chains」——**「principal」已在论文语汇里**（作为 future work）。我们的扩展 = 把这个 hook **提拔成正式贡献**。术语被 Lampson + 论文自身双重背书。

**⚠ 术语撞车（必避）**：论文**已有「type」** = `act.type ∈ {use,export,write,rotate,enroll,revoke}`（**操作种类**）。我们「role × type」的 type = **记录/资源类别**（secret/connection/policy）。**我们那个改名**（如 `resource class` / `record type`），别和 `act.type` 撞。

**⭐ 关键 scoping 决定（用户拍，直接影响 20 天风险）**：多写者+身份+团队对论文是**大扩展**——要改威胁模型（新增「控制部分而非全部写者」的对手）、加 2 条性质（**可验证作者身份** + **角色最小权限**）、加命题，并**refine 论文核心不变量**（Phase I「Uniform Recoverability / any-of-N 每凭据都能到 K」使所有凭据等价——我们要「不同 principal 不同权限 + 独立签名身份」）。**20 天里给一篇已证论文硬塞这套 + 补新证明，风险高、可能反削弱它。**
> **建议**：**第一篇（20 天）= 现有单用户 SUDP，按已证样子投**（至多轻润 + 把 §10 future-work hook 明确指向扩展）。**多写者+身份+团队整套 = 第二篇，单独排期。** 更低风险、更干净（SUDP=委托原语；第二篇=其上多 principal 身份/团队）。**除非** 20 天投稿**就是要展示团队/多写者能力**——那才塞，但更险。默认走前者。

**第二篇（扩展）要动的锚点（勘察给了精确位置）**：§3.1 party/trust（加多写者）、§3.2/3.3（加「可验证作者身份」+「角色最小权限」性质，新对手）、§5.1 roles（引入 owner/member）、**§5.1 Key Hierarchy + Phase I Uniform Recoverability + L3 any-of-N（直接冲突点：拆出「独立签名身份 ≠ wrapping 凭据」= principal≠authenticator）**、§5.2 Def 2 `act`（role×资源类别 挂这）、Phase II/III（签名+作者身份绑进 Σ/M，今天 M 无作者元数据）、§4.2 positioning 表 + §9（加轴列 + 新命题）。
**RFS 复用**：踢人 forward secrecy **不是新性质**，是论文已有 **RFS（Rotation Forward Secrecy）扩到多 principal offboarding**——接上，别另造。
**诚实边界（照论文口径）**：可用性/DoS 压不是灭；web keygen 服务端投毒前提；re-key 不免除轮换上游；CMC（运行时内存）仍 out-of-scope、靠 TEE 组合。

---

## B. 代码修改规格（**改动全在 SafeClaw core / backend；sudp core crate 不动**；没时间充分测试，故按「先隔离可测、再接线」排）

> **边界（与顶部一致，重要）**：下列改动**全部落在 SafeClaw core / backend（sudp crate 之上）**，**sudp core crate 保持不动**——它继续只当「seal + wrap + grant」的通用 codec。依据：sudp = 「AEAD codec only」，record 的 id/type/payload/status 本就在 core（`storage/item.rs` 的 `ItemPayload/ItemNs/StoredItem`）；`custody→UIK→K` 由 **core 经 UIK 产出 wrapping key**，sudp 仍只见「K + 一把 wrapping key」；团队「K 封给成员 UIK」走 backend `vault_keys`（本就云可见、core 管）。B1 的身份签名原语放 **core / 独立 crate，不进 sudp core crate**。（若最终发现某处非改 sudp 不可，必须是**通用**添加、且在此显式记录理由——默认不碰。）

**B1. crate 新原语(隔离、可黄金向量化,先做)**
- 加 **Ed25519 sign/verify** 与 `Principal`/`IdentityKey` 类型(签名身份);今天 crate 只有 WebAuthn**验**、无通用签名。
- 加 `record_signature_input(type, id, version, vault, body_hash, principal_id)`(照 `record_aad` 的长度前缀+域分隔;新域标签 `DS_SIG`)。
- **黄金向量**:`record_signature_input`、UIK id 派生(pubkey→id)、re-key generation 被签内容。(`item_id` 已有 pinned 向量 `storage/item.rs:359`,照此办。)

**B2. record 格式改动(最高风险,重点测)**
- `ItemPayload` 保留 `{name, body}` 密封;**把 `type`(ns)与 `status` 提到明文**,并进被签内容。
- wire 行 `vault_items` 增列:`type`、`status`、`sig`、`signer`(principal id/pubkey)。`item_id` 推导**不变**(仍 `HMAC(K_id, ns‖name)`,ns 参与但只是 id 输入)。
- daemon `StoredItem` 增 `sig/signer/type/status` 明文字段;fold/reconcile 在**验签后**才采纳。

**B3. 密钥层级(改 wrap 图,次高风险)**
- 加 UIK keypair;**custody(W_c 那套)改成包 UIK 私钥**;**K 用 HPKE 封给 UIK 公钥**(扩 `vault_keys.data` 带 UIK-wrap,x25519 地基已在)。按分层决定**撤直接 W_c→K**(或留作过渡,见 §C)。
- 复用现成:`primitives/wrap.rs`(对称包 UIK)、`primitives/kem.rs`/HPKE(K 封给 UIK)、`state/protected.rs` 的 authenticators 图(改成 UIK 图)。

**B4. generation / re-key**
- envelope(whole-blob + per-item)加 `generation`;加**被授权角色签名的 re-key 事件**;daemon「见更高的**签名有效** generation → 丢 K → 重解锁」;假 generation(无有效签名)一律忽略。

**B5. 验证 + 失败处理**
- 读者侧逐条 `verify(sig, signer_pubkey) && authorize(role, type)`;失败=A1.6(隔离+守旧+报警,不删不崩)。
- server 侧同样 verify+authorize 作写门(稳定性);keyset 删改在端点按角色 gate。

**B6. 顺序 / 兼容 / 风险**
- **顺序**:B1(crate 原语+向量,隔离可测)→ B2/B3(core 接线)→ B4 → B5 后端门。
- **兼容**:pre-launch;per-item v3 **正在 cutover**,把本次格式改动**并进 v3 cutover**(不另开迁移),符合 sync.md「升级即切换」。whole-blob 层若还在用,同一场升级搬。
- **风险最高两处**:B2(record 格式)与 B3(rewrap 图)。这两处务必**黄金向量 + 双运行时**(若 console TS 也要产/验签,SPEC 单一 + TS/Rust 双实现对向量,照 deposit 仪式的老规矩)。
- **`design/identity-uik-aik.md`** 是本修订的直接前身(Ed25519 单根、pubkey 自证 id、签名 config 单例 `body={data,sig}`、签名 members 锚、agent PoP);把它从「proposal」升级为本文的实现锚,phasing 对齐。

---

## C. 仍需拍板 / 开放项

1. **一稿 vs 两篇**(A3 推荐两篇,待用户最终定;决定论文包装,不改本文内容/代码)。
   - **仍开放（论文包装，不影响代码）**：一稿 vs 两篇是论文打包问题，仍是用户拍板项，不影响本文的代码/协议规格。
2. **v1 的 role×type 具体策略表**(A2 给了最小版,manager/view-only 是否 v1 就留槽)。
   - ✅ **RESOLVED**：v1 = 两角色 **Owner / Member**；member 可写 ns = `{secret, connection, connecting}`；其余（policy/stores/store_order/audit_retention/services + 未知 type）**owner-only**；keyset 操作端点层 owner-only。**manager / view-only 推迟**（已设计、留槽，待真需求再加行，SUDP 不动）。见 SM §附（写权限最终模型）+ team-edition §0.7(5) + 本文 A2。
3. **是否保留一条 `custody→K` 直连**作韧性(丢 UIK 时仍能解 K)——分层纯度 vs 恢复韧性的取舍(团队安全模型文档倾向纯分层 + 恢复码,此处复核)。
   - ✅ **RESOLVED（v1）**：走**纯分层** `custody→UIK→K`，**不留** `custody→K` 直连捷径（避免把 custody 和身份重新压回同层）。**丢光全部 custody 的账户恢复**（lost-all-custody）**显式推迟到 roadmap**，需更高「撤销/恢复权威」裁定，机制未来再定（SM §5 尾注「机制未来再定」，约 line 104/106；扩展性已由 A1.1 的 succession 钩子留好）。恢复码方案届时在此层加，SUDP core 不动。
4. **签名算法域**:Ed25519(身份/UIK/AIK)与现有 ECDSA-P256(WebAuthn 验 β)并存;确认互不污染域标签。
   - ✅ **RESOLVED（域标签定案）**：身份/UIK/AIK 签名用 `safeclaw/v1/*` 域标签（`config-sig` / `rekey` / `uik-succession` / `server-envelope` / `contact-token`），与 SUDP 协议层的 `sudp/v1/*`（如 `sudp/v1/item-sig`，A1.2）**两两不相交**，且与 WebAuthn ECDSA-P256 的 β 验签（不同算法族）互不重叠 → 三族域**确认不碰撞**。
