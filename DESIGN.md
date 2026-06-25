# sluice 実装計画書 — 大規模・継続バックアップ／ディザスタリカバリ・ツール

本書は、ユーザー自身が所有・管理する大量のファイルを対象とした、正規の個人／組織向けバックアップ&DRツール `sluice` の確定設計書である。restic / BorgBackup / Kopia / Duplicacy と同カテゴリの、暗号化・重複排除・継続バックアップシステムを Rust で構築する。実装はまだ存在せず（`/root/projects/shell` は空）、本書がゼロからのビルド指針となる。

---

## 1. 概要

### 何を作るか
`sluice` は、信頼できないストレージバックエンド（untrusted backend）上に、内容アドレス化された不変オブジェクトのみを追記していくことでリポジトリを構築する、モダンな継続バックアップ／DRツールである。ユーザーが鍵を完全に管理し、バックエンド（ローカルNAS、S3/MinIO/B2/GCS）は暗号文の不透明な塊しか見られない。

### 設計目標（ハード要件）
- **スケール**: 数百万ファイル／マルチTB／最大数十億チャンク。**RSS（常駐メモリ）は repo サイズに依存しないチューナブルな定数**に保つ。
- **増分バックアップ**: 初回以降は新規／変更データのみを処理・格納（定常状態は並列 `statx()` ウォークに収束）。
- **重複排除**: 既に格納された内容は再格納しない（plaintext-keyed-id によるコンテンツアドレッシング）。
- **圧縮**: 格納データを zstd で圧縮（非圧縮性データはスキップ）。
- **保存時暗号化**: ユーザーが鍵を管理。バックエンドは untrusted 前提。
- **スナップショット／リストア／検証**: 時系列スナップショット、フル&選択的リストア、整合性検証。
- **プラガブルなバックエンド**: ローカルFS と S3互換オブジェクトストレージ（オフサイトDR）。
- **クラッシュ整合性**: 中断・クラッシュしたバックアップがリポジトリを破壊しない（追記専用＋スナップショット最後書き）。
- **優れたCLI UX**: 進捗表示、スクリプタブルなJSON出力。Linux ファースト、クロスプラットフォーム志向。

### 中核となる確定アーキテクチャ判断（4つの分岐点）
| 軸 | 採用 | 理由 |
|---|---|---|
| インデックス戦略 | **オンディスク（redb）+ リビルド可能な repo セグメント** | 数十億チャンクで in-RAM map は OOM。authoritative map をディスクに置き RSS を有界化。 |
| AEAD nonce | **XChaCha20-Poly1305 / 192-bit ランダム nonce** | nonce 管理ステートゼロ、再利用フットガンなし。数十億 blob でも安全。 |
| ID キーイング | **keyed BLAKE3（plaintext）** | untrusted backend に対する confirmation 攻撃耐性。 |
| ビルダビリティ | **object_store + redb に最難部を委譲** | 小規模チームでも出荷できる。restic 系の可搬レイアウトを踏襲。 |

---

## 2. アーキテクチャ全体像

### データフロー図

```
                         ┌─────────────────────────────────────────────────────────┐
                         │            sluice backup engine (UI-agnostic)           │
                         └─────────────────────────────────────────────────────────┘

  [backup roots]
       │
       ▼                       ── rayon / 専用ブロッキングプール (CPU) ──        ── tokio (async I/O) ──
 ┌───────────┐  FileTask   ┌──────────────────────────┐  Chunk    ┌──────────────┐  CpuOut   ┌──────────┐
 │  SCAN     │────────────▶│ READ + FastCDC + keyed-  │──────────▶│ COMPRESS +   │──────────▶│  PACKER  │
 │ (ignore/  │ flume::     │ BLAKE3 + DEDUP-PROBE     │ flume::   │ ENCRYPT      │ flume::   │ (16 MiB  │
 │  jwalk)   │ bounded     │ (reader pool)            │ bounded   │ (zstd→AEAD)  │ bounded   │  pack組立)│
 └─────┬─────┘             └──────────┬───────────────┘           └──────────────┘           └────┬─────┘
       │ Reuse (unchanged)            │ Hit/Ref (dedup短絡)                                        │ FinishedPack
       │   バイパス                    ▼ Miss                                                      ▼ flume::bounded
       │             ┌─────────────────────────────┐                                       ┌──────────────┐
       │             │  DEDUP INDEX                │                                       │  UPLOADER    │
       │             │  memtable→xorf filter→redb  │◀──────────────────────────────────────│ object_store │
       │             │  →repo index segments       │   IndexCommit (アップロード確定後のみ)   │ put/multipart│
       │             └─────────────────────────────┘                                       └──────┬───────┘
       │                                                                                          │ durable
       ▼                                                                                          ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ TREE + SNAPSHOT FINALIZE (orchestrator): reorder buffer で per-file チャンクリスト復元 →                │
 │ ボトムアップに Tree(CBOR) を構築 → 全 pack/segment が durable になった後、Snapshot を最後に書く＝原子コミット │
 └──────────────────────────────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    Progress イベント (flume) ─▶ Reporter: indicatif | NDJSON | silent
```

### ステージ別パイプライン
1. **SCAN**: `ignore::WalkParallel` でルートを並列ウォーク。除外適用、分類、増分ゲート（stat-tuple 比較）。Unchanged は `Reuse` として木組立へ直送、CPUパイプラインを完全バイパス。
2. **READ + CDC + HASH + DEDUP-PROBE**（reader pool）: バッファ付きシーケンシャル読み込み（**mmap不使用**）→ streaming FastCDC → `chunk_id = blake3::keyed_hash(id_key, plaintext)` → index probe。Hit なら `Ref`（ルーティング情報のみ）を発行し重い処理を短絡。
3. **COMPRESS + ENCRYPT**（CPU pool）: zstd L3（非圧縮性スキップ）→ XChaCha20-Poly1305 シール。圧縮と暗号化を1チャンクで融合し L2/L3 キャッシュを温存。
4. **PACK**: sealed blob を ~16 MiB pack に追記、暗号化フッタ（blob ディレクトリ）を付与、`pack_id = BLAKE3(pack bytes)`。
5. **UPLOAD**（tokio）: `object_store` put / put_multipart。**durable 確定後にのみ** `IndexCommit` を発行。
6. **INDEX COMMIT**（単一 redb writer）: memtable + redb に挿入、キャップ到達でソート済み不変セグメントをフラッシュ。
7. **TREE + SNAPSHOT FINALIZE**: 全ステージ drain・全 pack/segment durable の後、root tree id を確定し **Snapshot を最後に書く＝原子コミット**。

---

## 3. リポジトリ／オンディスク形式 とデータモデル

### 不変条件（全サブシステムの土台）
> リポジトリは **不変・内容アドレス化・暗号化されたオブジェクトの追記のみ** で成長し、**Snapshot（唯一のコミット点）を最後に書く**。インプレース変更は一切しない。可変状態（lookup index、stat-cache）はすべてローカルのリビルド可能キャッシュに置く。

`type Id = [u8; 32]`（BLAKE3 出力）を全域で使用。

### リポジトリレイアウト（local FS と S3 で同一、restic 系譜）
```
repo/
  config                 # リポジトリパラメータ (version, repo_id, chunker, cipher, pack/chunk size); AEAD封緘
  keys/<keyid>           # ≥1: Argon2id params+salt + KEK封緘された master key（鍵追加=ローテーション）
  data/<aa>/<packid>     # pack ファイル。2-hex プレフィックスでシャーディング。data-blob と tree-blob を混載
  index/<aa>/<indexid>   # 不変ソート済みインデックスセグメント（dedup/location カタログ）; AEAD封緘
  snapshots/<snapid>     # スナップショットオブジェクト = 原子コミット点
  locks/<lockid>         # advisory ロック（exclusive が必要なのは prune のみ）
```
シャーディングは id 先頭バイト（256プレフィックス、設定で 2バイト/65536）。S3 パーティション分散とローカル inode 数の有界化のため。

### 2つの直交するハッシュ層
- **blob id**（data & tree）= `keyed-BLAKE3(id_key, plaintext)` — dedup キー AND 整合性リーフ。keyed なので、暗号文を持つ攻撃者でも「plaintext X が格納されているか」を判定できない（confirmation 攻撃耐性）。
- **pack id** = `BLAKE3(final pack bytes)`（**unkeyed**、暗号文をハッシュ）— 自己検証可能な不変ストレージ名。鍵なしでスクラバーが整合性検証可能。
- snapshot id / index id = `BLAKE3(serialized object bytes)`。

### Sealed Blob（pack 内で繰り返される原子格納単位）
```
blob = nonce(24) || AEAD_ct( zstd_or_raw(plaintext) ) || tag(16)
```
- AEAD = XChaCha20-Poly1305（デフォルト、192-bit ランダム nonce）。AES-256-GCM はリポジトリ単位で選択可（single-use key 派生で 96-bit nonce 問題を構造的に回避）。
- AAD = `repo_id(16) || format_version(1) || blob_kind(1: Data|Tree) || cipher_id(1) || key_epoch(4)`。クロスリポジトリ・スプライシング、ダウングレード、再型付けを検出。
- フレーミングオーバーヘッド 40 byte/blob（≈0.004% @ 1 MiB チャンク）。

### Pack ファイル（バックエンドに実際に PUT される単位）
```
[blob_0][blob_1]...[blob_n][sealed_header][header_len: u32 LE]
```
```rust
struct BlobEntry {
    id: [u8; 32], kind: BlobKind /*Data|Tree*/,
    offset: u32, length: u32 /*sealed*/, uncompressed_length: u32,
    compression: Compression /*None|Zstd{level,dict_id}*/, cipher: CipherSuite, key_epoch: u32,
}
struct PackHeader { entries: Vec<BlobEntry> }  // sealed_header = AEAD(meta_key, CBOR(PackHeader))
```
- パックディレクトリは **最大2回の小さな range-GET**（末尾4byte→header_len→header range-GET、または末尾64KiBを一括GET）で読める。
- フッタは index を pack 単独から完全再構築できる**真実の源**（DR パス）。
- **デフォルト pack target = 16 MiB**（sluice 既定 64 MiB から引き下げ、小ファイル選択リストアの read amplification を削減。64 MiB+ は cold/archive tier 用ノブとして予約）。
- **REPACK-BY-COPY 特性**: 各 sealed blob は自己完結（nonce+ct+tag）。prune は blob を**復号・再圧縮・再暗号化なしのバイトコピー**で再配置しオフセットを書き換えるだけ。

### Tree オブジェクト（Tree-kind blob、CBOR、Cairn 級メタデータ）
```rust
struct Tree { version: u8, nodes: Vec<Node> }   // name でソート → 決定論的 id
struct Node {
    name: Box<[u8]>,                              // OsStr バイト列（非UTF8 忠実）
    kind: EntryKind, /*File|Dir|Symlink|Fifo|Socket|CharDev|BlockDev*/
    mode: u32, uid: u32, gid: u32,
    mtime_ns: i64, ctime_ns: i64, atime_ns: i64, size: u64,
    content: Vec<Id>,                            // File: 順序付きチャンク id
    subtree: Option<Id>,                         // Dir: 子 tree blob id（Merkle 辺）
    link_target: Option<Box<[u8]>>,              // Symlink
    device: u64, inode: u64, links: u64, rdev: u64,  // ハードリンク検出 (device,inode,links)
    xattrs: Vec<(Box<[u8]>, Box<[u8]>)>,         // key でソート（決定論）
}
```
未変更ディレクトリ → 同一 CBOR → 同一 tree id → スナップショット間で自動 dedup。

### Snapshot オブジェクト（コミット点）
```rust
struct Snapshot {
    version: u8, time: OffsetDateTime, tree: Id /*root*/, paths: Vec<PathBuf>,
    hostname: String, username: String, uid: u32, gid: u32, tags: Vec<String>,
    parent: Option<Id>, program_version: String, summary: SnapshotStats,
}
```

### Config / Key
```rust
struct RepoConfig {
    magic: [u8;8] /*=b"SLUICE01"*/, version: u32, repo_id: [u8;32],
    chunker: ChunkerParams { min: u32, avg: u32, max: u32, gear_seed: [u8;32] },
    cipher: CipherSuite, pack_target: u64, chunk_avg: u32, shard_depth: u8,
    features: FeatureFlags { worm: bool, erasure: bool, /*...*/ }, created: i64,
}  // master key で AEAD 封緘 → バックエンドは cipher/chunker を黙ってダウングレードできない
```
Key file = `Argon2id{salt,m,t,p}` + `AEAD(KEK, master_key)`。`master --BLAKE3::derive_key--> {id_key, data_key, meta_key}`。

### シリアライズと決定論
trees / snapshots / headers / config / index は **ciborium による CBOR**（canonical profile: 固定フィールド順、ソート済みマップ、indefinite-length 禁止）。tree/snapshot id がこれらバイト列のハッシュなので決定論は load-bearing。**チェックインしたテストベクタ**でエンコーダ・ドリフトを防ぐ。msgpack はより小さいが、自己記述性と前方互換オプションフィールドのため CBOR を採用。

---

## 4. クレート構成（Cargo workspace）

```
sluice/                          # Cargo workspace root
├── Cargo.toml                   # [workspace] members + 共有依存バージョン
├── crates/
│   ├── sluice-core/             # 純粋型・ID・エラー・format定数（no_std寄り、UI/IO非依存）
│   │   ├── id.rs                # Id, ChunkId, PackId, BlobKind, Location
│   │   ├── format.rs            # Tree/Node/Snapshot/RepoConfig/BlobEntry + CBOR canonical
│   │   └── error.rs             # thiserror エラー型
│   ├── sluice-crypto/           # 鍵階層・AEAD・KDF・Argon2・seal/open 単一経路
│   │   ├── keys.rs              # KeySet, KeyFile, wrap/unwrap_master
│   │   ├── aead.rs              # BlobCrypto trait, XChaCha/AES-GCM 実装, AAD構築
│   │   └── hash.rs              # keyed/unkeyed BLAKE3, derive_key
│   ├── sluice-chunk/            # 自作 FastCDC v2020（key-derived gear）+ chunk_id
│   ├── sluice-index/            # memtable + xorf filter + redb cache + repo セグメント + compaction
│   ├── sluice-store/            # StorageBackend trait + Local/ObjectStore/S3Worm 実装 + Packer
│   ├── sluice-scan/             # ignore/jwalk ウォーカー + redb stat-cache + shadow tree 木組立
│   ├── sluice-engine/           # パイプライン編成（rayon/tokio）, backpressure, cancel/resume
│   │   ├── backup.rs            # backup フロー
│   │   ├── restore.rs           # RestorePlan, read-coalescing, metadata replay
│   │   ├── verify.rs            # 構造/read-data/subset スクラブ
│   │   └── prune.rs             # forget/prune, mark-sweep, repack-by-copy
│   ├── sluice-repo/             # Repository ハンドル（init/open, save/load_blob/tree, commit_snapshot）
│   └── sluice-cli/              # clap v4 バイナリ `sluice` + figment config + Reporter
│       └── main.rs
├── fuzz/                        # cargo-fuzz: pack/index/tree/snapshot/config デコーダ毎のターゲット
└── xtask/                       # golden vector 生成, リリース補助
```

依存方向は厳格に一方向: `core ← crypto, chunk, store ← index, scan ← repo ← engine ← cli`。`sluice-core` は I/O・UI に非依存で、エンジンと CLI を分離する seam を作る（FUSE/daemon フロントエンドの再利用を可能にする）。

---

## 5. 主要サブシステム

### 5.1 File discovery & 増分スキャン（`sluice-scan`）

**ウォーカー**: プライマリは `ignore::WalkParallel`（ripgrep のクレート）。work-stealing、ストリーミング（collect しない）、層状 gitignore セマンティクスが正しい。
```rust
WalkBuilder::new(root)
    .threads(n).same_file_system(one_fs).follow_links(false)
    .hidden(false).standard_filters(false).max_depth(d)
    .overrides(ov).add_custom_ignore_filename(".sluiceignore")
```
git_ignore はデフォルト **OFF**（バックアップツールは .gitignore に載っているだけでファイルを黙って落とすべきでない）、`--use-gitignore` で有効化。`--walker=jwalk` は単純 glob 除外のみ必要なユーザー向け高速パス。

**除外ルール（安い順に評価）**: (1) `--exclude/--include` glob を `ignore::overrides::Override`（globset）に一括コンパイル → (2) `--exclude-larger-than`（取得済み lstat から、追加 syscall なし）→ (3) CACHEDIR.TAG（先頭43byte が `Signature: 8a477f597d28d172789f06886806bc55` なら `WalkState::Skip`）→ (4) `--exclude-if-present FILE` → (5) ネストした `.sluiceignore`。名前は全域 OsStr/[u8] 扱い。

**分類とメタデータ**: 各エントリを `rustix::fs::statx`（STATX_BTIME|MTIME|CTIME）で1回 lstat。Symlink はデフォルト追わず raw bytes を `link_target` に格納。特殊ファイルは mode + rdev を記録し restore 時に mknod。content 読み込みは `OFlags::NOATIME`（自所有時、EPERM で通常 open にフォールバック）。

**増分ゲート（心臓部）**: authoritative は repo（親スナップショット tree）、速度はローカルの redb stat-cache（フルパスバイト列キー）。各通常ファイルで現在の stat-tuple `(size, mtime_s/ns, ctime_s/ns, inode, dev)` を point-lookup。
| 判定 | アクション |
|---|---|
| エントリなし | **New** — FileTask 発行、読み込み |
| kind 不一致 | **Changed** |
| (size, mtime, inode) 一致（+ ctime（`--ignore-ctime` 除く）, + inode（`--ignore-inode` 除く）） | **Unchanged** — キャッシュ済み順序付きチャンクリストを**ファイルI/Oゼロで再利用** |
| その他 | **Changed** |

cache 値はチャンクリストを **denormalize**（小ファイルは `SmallVec<[ChunkId;4]>` インライン、大ファイルは `Spilled(ChunkListId)`）。再利用は純粋ローカルで repo round-trip なし。`--read-all`/`--force` で全ファイル再ハッシュ、`rehash-after = 30d` で定期的内容再検証。

**木組立（有界メモリ内）**: 並列ウォーカーは非決定論的順序を返すため、木は walk 順では構築しない。redb の shadow tree テーブルに `[parent_slot: u64 BE][name bytes] -> ShadowNode` を書く。BE プレフィックスで子をグループ化し、name サフィックスで range-scan が canonical name 順を返す → 決定論的 CBOR tree blob → 同一 TreeId（サブツリー dedup 無料）。各ディレクトリ行に atomic pending-children カウンタ。子の content 完了でカウンタをデクリメント、0 で range-scan → CBOR シリアライズ → 同じパイプラインへ投入（tree-kind blob 化）→ TreeId を親行へ → 祖父をデクリメント（参照カウント post-order 完了、パイプライン化、開いているディレクトリ以上の RAM を要しない）。

**ハードリンク**: `nlink>1` を `DashMap<(dev,inode), NodeSlot>`（シャード化、病的時は redb spill）で coalesce。初回パスを通常格納、後続は同チャンクリスト参照、restore で `link()` 再現。

**有界メモリ要約**: RSS = ウォーカーフロンティア（dir handle）+ flume チャネルバッファ + redb ページキャッシュ + open-dir カウンタ。すべてファイル数に対し O(1)、木の高さに対し O(depth)。wide-dir / hardlink は redb spill。

### 5.2 Chunking & Deduplication（`sluice-chunk` + `sluice-index`）

**チャンキング = FastCDC v2020**（64-bit gear、normalized chunking NC=2）。Rabin（最遅）でも plain gear（窓が狭い）でもなく FastCDC を採用: cut-point skipping（min まではハッシュ評価せず）+ optimized hash judgment + normalized chunking（avg 前後で MaskS/MaskL を切替えサイズ分布を締める）で Rabin 級の dedup を gear 速度（~3-10x）で実現。
```
i=min; if len<=min {return len}; hi=min(avg,len); hash=0;
while i<hi { hash=(hash<<1)+gear[data[i]]; if hash & MASK_S == 0 {return i+1}; i+=1 }  // strict
hi=min(max,len);
while i<hi { hash=(hash<<1)+gear[data[i]]; if hash & MASK_L == 0 {return i+1}; i+=1 }  // loose
return hi  // max でのハードカット（敵対入力でも chunk <= max を保証）
```
- **パラメータ**: min 256 KiB / avg 1 MiB / max 4 MiB。`config` に**ピン留め**（変更は全既存データとの dedup を失うため明示的不連続として拒否）。avg は最大 4-8 MiB まで設定可（index メモリ vs dedup 粒度のノブ）。
- **key-derived gear テーブル（セキュリティ上の決定的選択）**: `gear = BLAKE3::derive_key("sluice fastcdc gear v1", master) -> [u64;256]`。チャンク境界（pack サイズ列）をバックエンドに対し**秘匿**し、chunk-size フィンガープリンティング／watermarking 攻撃を封じる。stock `fastcdc` クレートは gear がハードコードなので、custom table を受ける ~150行の自作 FastCDC を出荷。`fastcdc::StreamCDC` は property/vector テストのオラクルとして使用。
- **mmap 不使用**: ファイルは大きな `BufReader` 経由でストリーミングチャンカ（max_size 上限のリングバッファ）へ。ピーク RAM は O(max_size)、SIGBUS・network-FS ハザードなし。

**コンテンツアドレス = keyed BLAKE3(plaintext)**: `chunk_id = blake3::keyed_hash(id_key, plaintext)`。dedup キー・整合性チェック・index キーを兼ねる。pack_id は unkeyed BLAKE3(ciphertext)（鍵なし検証可能）。両者を混同しない。

**dedup ⟷ 暗号化**: 順序は **dedup判定（plaintext）→ 圧縮 → 暗号化**。暗号化は**非収束**（各 novel チャンクは fresh ランダム 192-bit nonce）。同一 plaintext を2回格納すると異なる ciphertext → 暗号文比較では dedup 不可 → plaintext-keyed-id index が存在理由。dedup スコープは repo 鍵（クロスリポジトリ dedup なし = untrusted backend 上のプライバシー機能）。

**dedup index（3層）**:
```rust
#[repr(C)] struct ChunkLocation { pack_ordinal: u32, offset: u32, length: u32, uncompressed_len: u32, flags: u8 }  // 17B LE固定幅
```
- **Tier A — REPO INDEX**（authoritative、untrusted backend上）: 不変・暗号化・内容アドレス化 `index/<id>` セグメント。各セグメント = ソート済み run。`header{ entry_count, min_id, max_id, pack_table: Vec<PackId>, filter: BinaryFuse8 }` + 固定幅ソート済みエントリ配列 → zstd → XChaCha20-Poly1305。可搬・言語中立・no-DB の dedup 真実源。
- **Tier B — ローカルキャッシュ**（trusted、redb）: 全 import 済みセグメントの完全マテリアライズドミラー + pack table + stat-cache。テーブル: `chunks(id->loc)`, `packs(ordinal<->pack_id)`, `stat_cache((dev,ino)->StatEntry)`, `meta(imported segment-ids, params)`。open 時に `index/` を LIST し未記録セグメントを import（rebuild/multi-client/warmup を単一経路で処理）。喪失してもデータ喪失なし。
- **Tier C — PACK FOOTERS**（究極のリビルド源）: `rebuild-index` が `data/*` を LIST しフッタを range-GET して replay。

**ルックアップパス（dedup_probe）**:
```
1. memtable シャード参照（今回 run）→ hit なら location 返却
2. in-RAM filter が DEFINITELY ABSENT（live Bloom 否定 AND 全 segment filter 否定）→ MISS、格納、ディスクI/Oゼロ（novel データのホットパス）
3. filter POSITIVE → redb.get(id): 見つかれば HIT、なければ false positive → MISS、格納
```
- **In-RAM working set**: 256シャード memtable（`DashMap<ChunkId,ChunkLocation>`、get-or-reserve で intra-run 重複を collapse）+ per-segment `BinaryFuse8`（xorf、~9 bit/chunk、FPR ~0.39%、RAM budget で sheddable）+ live `fastbloom`。
- **メモリ予算**: filter が支配項（100M→~113MB、1B→~1.13GB、チューナブル/sheddable）。memtable キャップ（50-200MB）。redb ページキャッシュは reclaimable。**RSS は repo サイズに非依存の定数**。
- **コンパクション**: フラッシュ毎に小セグメント追加。size-tiered/leveled merge でセグメント数を O(log) に。prune に畳み込む。

**安全性の背骨**: false MISS → 重複格納（安全・内容同一・prune で回収）。false HIT は**不可能**（filter は false positive のみ、redb get で確定）。chunk_id 衝突は BLAKE3 birthday ~2^-128 で無視可、さらに dedup hit 毎に **length 等価ガード**を無料追加。

### 5.3 Compression（`sluice-crypto` 内）

**zstd（`zstd` クレート / libzstd）**。デフォルト level 3（near-lz4 速度、堅実な比率、zstd が CPU 予算を支配しパイプライン throughput を決める）。preset: `fast`=1, `default`=3, `better`=9, `max`=19。level 9 超は per-blob ~1 MiB 窓では逓減（クロスチャンク冗長は CDC dedup が捕捉）。各 rayon worker が再利用可能な `zstd::bulk::Compressor`/`Decompressor`（libzstd context は非Sync）を所有。**skip-if-incompressible**: 圧縮後が plaintext の 97% 以上なら verbatim 格納し `Compression::None`（JPEG/MP4/zip の膨張防止）。`None` でも AEAD は必ず適用。

**辞書（任意）**: data チャンクは min 256 KiB で利得小 → デフォルト OFF。**tree/メタデータ stream に限定**（CBOR ディレクトリは小さく構造類似）。`zstd::dict`（ZDICT）で訓練、不変 AEAD 封緘 `dict/<id>` に格納、`BlobEntry.dict_id` で参照。dedup は plaintext id にキーするので辞書は ciphertext のみに影響、後から追加・再訓練可能、再圧縮不要。**辞書オブジェクトは GC ルートとして pin**（喪失すると blob が復号不能）。

**解凍爆弾対策**: 記録された `plaintext_len` 分だけ確保、それ以上の出力を拒否。

### 5.4 暗号化 & 鍵管理（`sluice-crypto`）

**順序 = COMPRESS-THEN-ENCRYPT**（必須）。各 blob は独立 zstd フレームで圧縮するため CRIME/BREACH は非該当。pack フッタも AEAD 封緘 → バックエンドは whole-pack サイズ（~16-64 MiB）しか見えず、per-chunk/per-file サイズ・名前・木構造は不可視。

**AEAD = XChaCha20-Poly1305**（RustCrypto `chacha20poly1305`、デフォルト）。192-bit nonce → ランダム nonce がステートゼロで衝突安全（birthday q²/2^193、2^40 blob で ~2^-113）、全 CPU で constant-time、AES-NI 不要。zstd が CPU 支配なので AEAD 差は隠れる。
- **任意の代替 = AES-256-GCM**（`aes-gcm`、AES-NI ホスト向け、`cpufeatures` で runtime 検出、`init` で選択し `config` に固定）。**96-bit nonce ハザードを継承しない**: ランダム 32-byte salt → `K_blob = BLAKE3::derive_key("sluice.v1 aes-gcm blob-key", data_key||salt)` → 全ゼロ 96-bit nonce で single-use key（AWS-ESDK/Tink/NIST SP 800-108 パターン）。
- 究極の paranoid 向けに **AES-256-GCM-SIV**（`aes-gcm-siv`、RFC 8452、misuse-resistant、~2x 遅い）。
- RustCrypto を選ぶ理由: ring は XChaCha も per-blob-key 経路も持たず BoringSSL asm を引く。age は recipient FORMAT で抽象層が違う（pack 内の数千 sub-blob 封緘には不適）。RustCrypto は `aead::AeadInPlace` で全 primitive を提供、`zeroize` 統合、SIMD バックエンド。

**鍵階層**:
```
passphrase --Argon2id(salt,m=256MiB,t=3,p=1)--> KEK --AEAD--> wraps random 256-bit MASTER
MASTER --BLAKE3::derive_key(ctx)--> { id_key, data_key, meta_key }
```
- **passphrase → KEK**: `argon2` クレート、Argon2id（RFC 9106）。params+16byte salt を key オブジェクトに格納。
- **KEK → master**: master は `init` で生成した1個のランダム 256-bit。`XChaCha20Poly1305(KEK, nonce, master, aad=repo_id||KEY_VERSION)` で封緘し `keys/<keyid>`。**複数 key オブジェクトが同一 master を異なる passphrase で wrap** → passphrase ローテーションが O(1)（新 key を追加、旧を削除、データ無触）。
- **master → subkey**: `blake3::derive_key(context, master)`（HKDF-like、subkey 毎に domain-separation context）。`id_key`（chunk/tree id）, `data_key`（per-blob AEAD）, `meta_key`（config/head/index 封緘）。HKDF-SHA256（`hkdf`）は監査者向け drop-in 代替。
- **3層ローテーション**: (1) passphrase ローテーション = master 再 wrap、O(1)、常用。(2) data-AEAD-key ローテーション = `key_epoch` bump、`data_key = derive_key("sluice.v1 data-key e{N}", master)`、新 blob は epoch N で封緘、旧 pack は記録 epoch で読める、`id_key` 不変なので dedup/index identity 完全保存（data_key 露出疑い時）。(3) master/id_key ローテーション = chunk_id が変わる＝実質新リポジトリ（真の master 漏洩時のみ）。
- **衛生**: 全秘密は `secrecy::SecretBox`/`zeroize::Zeroizing` + `ZeroizeOnDrop`。passphrase は `rpassword` で zeroizable バッファへ。`subtle` で constant-time 比較。core dump 無効化（prctl/RLIMIT_CORE）+ 任意の mlock 推奨。バックエンドは鍵を一切受け取らない。

### 5.5 ストレージバックエンド（`sluice-store`）

**判断: trust boundary で authority を分割**。
- untrusted repo 上 = **カスタム不変ソート済み AEAD 封緘セグメント**（SQLite/redb ではない。DB は in-place mutation を要し S3 で原子的に不可能、不変条件に違反）。
- ローカル = **redb**（dedup/lookup ホットパスのリビルド可能キャッシュ）。

```rust
enum FileType { Config, Key, Pack, Index, Snapshot, Lock }
struct PutOpts { if_not_exists: bool, object_lock: Option<RetainUntil>, storage_class: Option<StorageClass> }

#[async_trait] pub trait StorageBackend: Send + Sync + 'static {
    fn location(&self) -> &str;
    async fn get(&self, ty: FileType, id: &Id) -> Result<Bytes>;
    async fn get_range(&self, ty: FileType, id: &Id, r: Range<u64>) -> Result<Bytes>;
    async fn get_ranges(&self, ty: FileType, id: &Id, rs: &[Range<u64>]) -> Result<Vec<Bytes>>; // 結合リストア読み
    async fn put(&self, ty: FileType, id: &Id, data: Bytes, o: PutOpts) -> Result<()>;            // 原子 create
    async fn put_multipart(&self, ty: FileType, id: &Id, body: ByteStream, o: PutOpts) -> Result<()>;
    fn list(&self, ty: FileType) -> BoxStream<'_, Result<(Id, ObjectInfo)>>;
    async fn stat(&self, ty: FileType, id: &Id) -> Result<ObjectInfo>;
    async fn remove(&self, ty: FileType, id: &Id) -> Result<()>;
}
#[async_trait] pub trait ColdTier { // S3 のみ
    async fn restore_object(&self, ty: FileType, id: &Id, days: u32, tier: ThawTier) -> Result<()>;
    async fn restore_status(&self, ty: FileType, id: &Id) -> Result<RestoreStatus>;
}
```
**3実装の意図的分割**:
- `LocalBackend`（native `std::fs` + `rustix`）: `tmp/<rand>` → `File::sync_all` → 原子 rename → **`fsync(parent dir)`**。`object_store::LocalFileSystem` はディレクトリエントリを fsync しない（実durability gap）ため自前実装。`if_not_exists` は `O_EXCL`、ロックは `flock`、object_lock は `chattr +i`（FS_IMMUTABLE）で任意エミュレート。
- `ObjectStoreBackend<T: ObjectStore>`（`object_store` クレート）: S3/GCS/Azure/MinIO/Ceph/HTTP。`if_not_exists` → `PutMode::Create`（If-None-Match:*）、`get_ranges` → `object_store::get_ranges`、大 pack → `put_multipart`（CompleteMultipartUpload でのみ可視＝原子）。**「小チームで出荷できる」レバー**。
- `S3WormBackend`（`aws-sdk-s3`）: WORM/cold-tier feature 有効時。`object_store` が公開しない Object Lock、RestoreObject、storage-class 遷移用。`ObjectLockMode + RetainUntilDate` で書き、`ColdTier` を実装。object_store と合成可能（bulk PUT/GET は object_store、lock/thaw/class は aws-sdk-s3）。

### 5.6 インデックス（`sluice-index`、5.2 と一体）

repo セグメント形式と redb テーブルは 5.2 参照。v1 はセグメント全体を fetch+decrypt して redb に ingest（シンプル、有界、定常状態ではセグメントに二度と触らない）。v2 はブロック構造（4KiB 暗号化エントリブロック + footer の authenticated sparse key→block-offset テーブル）で ranged decryption/binary search を可能にする。ホットパスは memtable → xorf filter → redb の順で**有界 RSS**。DR は `rebuild-index`（pack フッタから streaming + memtable-capped 再構築）。

### 5.7 整合性（`sluice-engine/verify.rs`）

**2つの噛み合う Merkle 構造 + per-blob MAC**:
- (a) **CONTENT DAG**: snapshot --BLAKE3--> root tree --(subtree id)--> trees --(content id)--> chunks。1スナップショット id を信頼すれば到達可能な全バイトを推移的に認証（git 様）。リーフ/辺 MAC = `keyed-BLAKE3(id_key,...)` = リポジトリの HMAC、かつ confirmation 攻撃耐性。
- (b) **STORAGE 層**: `pack_id = BLAKE3(pack bytes)` がコンテナを認証、AEAD Poly1305 tag が各 blob を独立に認証。

**1ビット反転は {pack-id 不一致, AEAD tag 失敗, 再計算 chunk/tree id 不一致} のいずれかで必ず捕捉**。

**VERIFY レベル**: (1) 構造（全参照 id が index に解決、DAG 完全到達、dangling なし、roaring bitmap で有界）→ (2) presence（全参照 pack を stat、期待サイズ）→ (3) `--read-data`（全 pack DL、pack-id 再計算、各 blob 復号→解凍→keyed-BLAKE3 再計算==id）→ (4) `--read-data-subset N/M`（低 egress 継続スクラブ、Cairn graft。**実装済み**: `verify --sample <PERCENT>`、OS CSPRNG + 部分 Fisher-Yates で一様サンプリング）。

**SELF-HEAL（任意、config gated、Streven graft）**: 各 pack の固定サイズシャードに Reed-Solomon erasure（`reed-solomon-simd`）、parity を sibling オブジェクト + manifest に格納。`verify --repair` が parity から失敗 pack を再構築。「検出するが修復できない bitrot」ギャップを閉じる。

---

## 6. 並行処理・パイプライン設計

### トポロジ（2つの OS スレッドプール、スレッド非共有、flume のみで橋渡し）
1. **tokio multi-thread runtime**（worker_threads ~4）: 全 async バックエンド I/O、retry/backoff、CancellationToken、シグナル処理、進捗描画。
2. **専用 CPU プール**（`available_parallelism()`）: compress+encrypt ワーカーループ。
3. **専用 reader プール**（`min(cores,8)`、`--read-concurrency`）: buffered read + FastCDC + keyed-BLAKE3 + dedup-probe。

**唯一のクロスプール相互作用 = `flume::bounded` の enqueue/dequeue**。reader/CPU 側は blocking `recv()`/`send()`、tokio 側は `recv_async()`/`send_async()`。**flume が要**（1チャネル型が両端を露出、crossbeam（sync専用）+ tokio::mpsc（async専用）の不格好な受け渡しを回避）。

### rayon/tokio 規律（contention なし）
- async fn は reader/CPU プールで**絶対実行しない**。CPU ループは tokio worker で**絶対実行しない**。
- CPU worker は backpressure 下で blocking send に park してよい（パイプラインは真に I/O-stall）→ だからこそ blocking ループは**専用プール**に置き rayon グローバルプールを使わない。`rayon::par_iter` は短い data-parallel sub-task（oversized chunk の並列ハッシュ、verify/restore fan-out）のみに予約 → park した worker が par_iter を starve させない。
- 総スレッド数 ≈ cores + ~4 tokio + readers。任意の `core_affinity` ピン留めで CPU プールを I/O コアから外す。

### Backpressure & 有界メモリ
全 edge が `flume::bounded` → エンジン全体が1本の backpressure チェーン: 遅いアップロード → upload semaphore 飽和 → packer ハンドオフ不可 → blob_q 満杯 → CPU worker が send に block → chunk_q 満杯 → reader が block → file_q 満杯 → scanner block。

**ピーク RSS = Σ(channel cap × max item size) + in-flight packs + memtable** = すべて定数。例（~16 cores）:
| 項目 | サイズ |
|---|---|
| chunk_q = 2×cores×4 MiB | ~128 MiB |
| blob_q | ~128 MiB |
| in-flight packs = 16×16 MiB | ~256 MiB |
| memtable | ~128 MiB |
| redb cache（mmap、reclaimable、予算外） | — |
| **合計（worst case）** | **~0.6-0.8 GiB** |

単一 `--memory-limit` ノブから全容量を導出し RSS を目標以下に維持。

### 順序・整合性
1. 内容アドレス冪等性（同一 chunk/pack 再書き込みは no-op、retry/並行バックアップ conflict-free）。
2. durability 順序 packs→index→trees→snapshot（各 committer の下流位置で構造的に強制）。
3. per-file チャンク順は reorder buffer（`DashMap<FileId, FileAssembly>`）で復元。
4. within-run single-store（`DashMap<ChunkId, PendingLoc>` の compare-and-insert claim）。
5. インプレース変更なし → クラッシュは回収可能 orphan のみ。
6. snapshot PUT/rename が唯一の linearization 点。

### 終了・キャンセル・レジューム
- **正常終了** = チャネルクローズ連鎖（scanner が Arc-counted sender を drop → 各ステージ drain/flush/drop → orchestrator が join → Snapshot 書き込み）。
- **キャンセル**（SIGINT/SIGTERM → `tokio_util::CancellationToken`）: 1回目 = graceful drain（スキャン停止、in-flight pack はアップロード完了させ segment flush、snapshot **なし**で終了）、2回目 = hard abort（アップロードキャンセル、`MultipartUpload::abort` で dangling part 回避、orphan 残置）。どちらも snapshot 未書き込みゆえリポジトリ整合。
- **レジューム** = 暗黙（定期 index-segment flush が durable チャンクをチェックポイント → 次回 run の増分ゲート + dedup が既アップロード分をスキップ）。任意の redb resume journal（run_id → 完了パス+mtime）で完了ファイル再読み込みも回避。

---

## 7. CLIコマンド設計 と config

### コマンドサーフェス（clap v4 derive、バイナリ `sluice`）

**グローバルフラグ**（全 `global=true`、env-backed）: `--repo/-r`（$SLUICE_REPO、`/path`・`s3://bucket/prefix`・`b2:`・`azure:` を object_store へ）, `--config/-c`, `--password-file`, `--password-command`, `--cache-dir`, `--threads`, `--progress auto|plain|json|none`, `--json`, `-v/-q`（repeatable）, `--no-lock`, `--limit-upload/--limit-download`, `--color auto|always|never`。

| サブコマンド | 主オプション |
|---|---|
| `init` | `--cipher xchacha\|aes-gcm`, `--chunk-avg`, `--pack-size`, `--compression`, `--copy-params-from`, `--worm` |
| `backup <paths..>` | `--exclude/--iexclude/--exclude-file`, `--exclude-caches`, `--exclude-larger-than`, `--one-file-system`, `--tag`, `--host`, `--parent`, `--force`, `--dry-run`, `--read-concurrency` |
| `snapshots` | `--tag/--host/--path/--group-by/--latest N/--compact` |
| `ls <snap[:subpath]> [path]` | `--long/--recursive/--json` |
| `restore <snap[:subpath]> --target DIR` | `--include/--exclude/--iinclude`, `--overwrite always\|if-changed\|if-newer\|never`, `--delete`, `--verify`, `--sparse`, `--dry-run` |
| `dump <snap> <path>` | tar で stdout へストリーム |
| `diff <snapA> <snapB>` | `--metadata` |
| `verify` | 構造（既定）, `--read-data`, `--read-data-subset N/M\|P%`, `--check-unused`, `--repair-from <src>`, `--reconstruct` |
| `forget` | `--keep-last/hourly/daily/weekly/monthly/yearly/--keep-within DUR/--keep-tag`, `--group-by`, `--dry-run`, `--prune` |
| `prune` | `--max-unused`, `--max-repack-size`, `--dry-run`（forget から分離） |
| `mount <dir>` | feature `mount`、fuser |
| `key add\|list\|passwd\|remove`, `tag`, `cache`, `repair`, `stats`, `unlock`, `cat`, `completions`, `man` | — |

**スナップショットセレクタ**は git 流: 一意 hex プレフィックス、`latest`、`latest:host:/path`。曖昧プレフィックスは候補列挙してハードエラー。

**安定 exit code（ドキュメント化された API）**:
| code | 意味 |
|---|---|
| 0 | OK |
| 1 | generic |
| 3 | バックアップ完了（読めないソース警告あり）／リストア不完全 |
| 10 | repo not found |
| 11 | wrong password / 復号不可 |
| 12 | lock held |
| 13 | verify が破損検出 |

破壊的操作（forget/prune/restore --delete）は plan を表示し `--yes` がなければ確認を要求。

### Config & secrets

**Config（`figment` で層状マージ）**: 組込 Defaults → `/etc/sluice/config.toml` → `$XDG_CONFIG_HOME/sluice/config.toml`（`etcetera` で解決）→ `SLUICE_*` env → CLI フラグ（**CLI が常に勝つ**、precedence は total order でテスト）。TOML via serde。named repo profile（url、region/endpoint、retention、tags、exclude、cache_dir、concurrency、bandwidth、compression/chunk）を保持、**secret はインライン格納しない**。
```rust
struct Config {
    default_repo: Option<String>, repos: BTreeMap<String, RepoProfile>,
    backup: BackupDefaults, retention: RetentionPolicy, limits: Limits, cache_dir: Option<PathBuf>,
}
struct RetentionPolicy {
    last: Option<u32>, hourly: Option<u32>, daily: Option<u32>, weekly: Option<u32>,
    monthly: Option<u32>, yearly: Option<u32>, within: Option<jiff::Span>, tags: Vec<String>,
}
```
**パスワード解決チェーン**（`PasswordSource` trait）: `--password-file` → `--password-command`（exec し stdout 読み、pass/1Password/vault 統合）→ `$SLUICE_PASSWORD`（非推奨）→ OS keyring（`keyring`、feature-gated）→ 対話 TTY（`rpassword`、no-echo）。**`--password <value>` フラグは意図的に存在しない**（`ps`/履歴漏洩）。S3 認証は標準 AWS chain（env、~/.aws、IMDS）を object_store が処理、config 平文には置かない。全鍵素材は `secrecy::SecretString`/`SecretVec` + zeroize-on-drop、`tracing` の secret フィールドは redact。

### エンジン→UI seam（エンジンは UI 非依存）
```rust
pub enum Progress {
    ScanProgress { files: u64, dirs: u64, bytes: u64 },
    FileStarted { path: Arc<Path>, size: u64 },
    BlobStored { plaintext: u64, compressed: u64, dedup_hit: bool },
    PackUploaded { id: PackId, bytes: u64 },
    FileDone { path: Arc<Path>, status: FileStatus }, // New|Changed|Unmodified
    ThawWaiting { pack: PackId, eta: Option<jiff::Span> },
    Warning { path: Option<Arc<Path>>, error: String },
    Done(Summary),
}
trait Reporter { fn handle(&mut self, ev: Progress); fn finish(self: Box<Self>); }
```
Reporter は `flume::Receiver<Progress>` を消費 → `indicatif` MultiProgress | NDJSON（serde_json）| silent。TTY 検出は `console::user_attended`（`CI`/`NO_COLOR` 尊重）。`tracing-indicatif` がログとバーを調停し干渉を防ぐ。

---

## 8. リストア・検証・prune/GC

### フル + 選択的リストア
1. セレクタ解決 → snapshot → root tree。
2. tree DAG を stream-walk（有界メモリ）、include/exclude `globset` を**早期適用**してサブツリーを剪定（`snap:/sub/path` で walk ルート制限）。
3. **RestorePlan 構築**: 各ファイルの順序付きチャンクリストを BlobRef に解決、`BTreeMap<PackId, Vec<BlobJob>>` に**反転**。各 BlobJob は range・plaintext_len・`SmallVec<FileTarget{path, offset}>` を持ち、複数ファイル共有チャンクを**1回だけ fetch して fan-out**。
```rust
struct BlobJob { range: Range<u64>, plaintext_len: u32, targets: SmallVec<[FileTarget; 1]> }
struct RestorePlan { by_pack: BTreeMap<PackId, Vec<BlobJob>>, total_bytes: u64, files: u64 }
```
4. **Read-coalescing**: pack 内で job を offset ソート、gap < 閾値 の range を単一 ranged GET に merge。in-flight pack を semaphore で有界化。
5. **Cold-tier 対応**（Streven graft）: pack の storage class が Glacier/Deep-Archive なら `RestoreObject`（thaw）発行 → poll/park してから range-GET、thaw ETA を進捗表示。
6. **Content phase**: ディレクトリを top-down 事前作成、ファイルを `fallocate`（sparse-aware）preallocate、pack を tokio 並行 fetch → 復号（AEAD 認証）→ zstd 解凍（rayon）→ 正しいオフセットへ `pwrite`/`write_at`（**ロックフリー並列 out-of-order 書き込み**）。`moka` LRU で hot 共有 blob をキャッシュ。
7. **Metadata replay**（Cairn-rich、順序が肝）: owner/mode → xattr（`xattr`）→ mtime（`filetime`）を**ボトムアップ**（子書き込みが親 dir mtime を壊さない）。symlink/fifo/device を `rustix`/`nix` で再作成。hardlink は `HashMap<(dev,inode), PathBuf>` で初出にリンク。
8. **Overwrite policy**: `if-changed` はターゲット再ハッシュで同一ファイルをスキップ → **リストアを冪等・レジューマブル**化。`--delete` で余分削除、`--verify` で書き込み後 keyed-BLAKE3 再計算。未対応ターゲット機能（xattr/hardlink 非対応 FS、Windows ACL）は fail でなく warn、per-file エラーは収集して exit code 3。

### 検証
5.7 参照。構造（既定）→ presence → `--read-data` → `--read-data-subset`（決定論的回転サンプリング）。破損レポートは blob → 影響ファイル/snapshot を逆引き。

### forget / prune / GC（**分離が肝、Streven graft**）
- **`forget`** = retention policy に従い snapshot オブジェクト削除（安価・頻繁）。retention bucketing: newest→oldest スキャンで last/hourly/daily/weekly/monthly/yearly バケットに割り当て、各バケット先頭を keep、keep-within・keep-tag と union。
- **`prune`** = 高価な mark-sweep + repack（S3 egress+PUT を伴うためメンテナンス窓でスケジュール）。

**prune アルゴリズム**（mark-and-sweep、roaring bitmap、exclusive lock）:
1. exclusive prune lock 取得。non-stale なバックアップロックがあれば**拒否**（並行バックアップ安全性はこのロックに依存しない、prune 削除安全性のみ）。
2. **MARK**: 残存全 snapshot の tree DAG を walk、各 live blob id → dense u64 ordinal を `RoaringTreemap` にセット（1e8+ blob でも有界 RSS）。
3. **PLAN**（index から pack 毎）: all-dead → 削除、partially-live（live-ratio < 70% 等）→ repack、mostly-live → keep（churn/egress 回避）。
4. **REPACK-BY-COPY**: live sealed blob を**復号/再圧縮なしでバイトコピー**して新 pack へ、新 index segment を書く（移動エントリを supersede）、ここで segment compaction も実施。
5. **DELETE**: 旧 pack + superseded segment を**最後に**削除（新 pack+index が durable になった後）。クラッシュ → 旧新両方に blob 重複（無害、次回 reconcile）。live データは決して失われない。
6. **ORPHAN**: `data/` vs index を比較、indexed されておらず grace period 超過の pack（クラッシュ/並行バックアップ由来）を削除可能。

**WORM 相互作用**: S3 Object Lock COMPLIANCE 下では prune は retention 失効済みオブジェクトのみ回収可 → **retention >= バックアップ頻度**が必要。GOVERNANCE は特権早期削除を許容。ランサムウェア耐性の代償として config で明示。

---

## 9. セキュリティモデル

### 脅威モデル（untrusted backend）
- **Trusted**: クライアントホスト、passphrase、ローカル CSPRNG、コード。鍵は client RAM に一時的にのみ平文存在（zeroize）。
- **Untrusted**: バックエンド（local NAS、S3/MinIO/B2/GCS）。honest-but-curious かつ**能動的に悪意ある**可能性: 読み・コピー・withhold・削除・並べ替え・replay・破損・改竄を試みうる。object count・pack サイズ・timestamp・アクセスパターン/タイミングを観測可能。passphrase/鍵は決して保持しない。

### 保証
| 性質 | 内容 |
|---|---|
| **機密性** | バックエンドは compress-then-AEAD 暗号文のみ見る。pack count/サイズ・総量・アクセスタイミング・粗い集約圧縮性は漏れるが、ファイル名・ファイルサイズ・per-chunk サイズ・ディレクトリ構造・内容は漏れない（tree オブジェクト AND pack フッタが暗号化）。**key-derived gear 境界**で per-blob サイズも秘匿（whole-pack サイズのみ漏洩）。 |
| **完全性/真正性** | Poly1305 tag + unkeyed pack-name hash + keyed-Merkle id で、いかなるオブジェクトも検出されずに偽造・改竄不可。keyed id が confirmation/known-plaintext 攻撃も封じる。 |
| **鮮度/可用性** | rollback/削除は**検出可能**（epoch-chained sealed `head` + ローカル trust anchor + verify）。**防止/修復は運用的にのみ**（WORM + versioning + erasure coding + multi-backend）。 |

### 全リポジトリの鮮度（anti-rollback）
内容アドレッシングは「どの snapshot が存在すべきか」を語れないため、authenticated・hash-chained・monotonic-versioned な `head` を追加:
```rust
struct Head { epoch: u64, snapshots: Vec<Id>, index_segments: Vec<Id>, prev_head: Option<Id>, time: i64 }
// meta_key で封緘、epoch を AAD に、毎バックアップ/prune 後に最後書き
```
クライアントは last-seen epoch+head id をローカルに trust anchor として保持。open 時に `head` を fetch・tag 検証し、epoch 後退・chain 断絶で**警告**（rollback/truncation シグナル）。バックエンドは head を**偽造できない**（鍵なし）。せいぜい旧 head を replay できるが anchor + prev_head chain で露見。

> **crypto は検出、WORM/erasure は防止/修復** — これが正直で完全なストーリー。crypto は backend にデータ保持を**強制できない**ため、防止は委譲する。

### 残存漏洩（正直な会計）
pack サイズ・object count・アクセスタイミング（high-threat ユーザー向けに任意の size-bucket padding、ストレージコストと引き換え）。Out of scope: 鍵常駐中のクライアントホスト侵害、passphrase/rubber-hose 侵害、集約サイズ/タイミングメタデータ。

---

## 10. 依存クレート一覧

| クレート | 用途 |
|---|---|
| **ignore** | プライマリ並列・ストリーミングディレクトリウォーカー（層状 gitignore、glob override、same_file_system、WalkState 剪定） |
| **jwalk** | `--walker` 高速パス（単純 glob 除外時の最大 readdir throughput） |
| **rustix** | statx（ns mtime/ctime/btime）、O_NOATIME、openat/readlinkat、mknodat、fsync(dir)、O_EXCL、flock、FS_IMMUTABLE |
| **redb** | ローカル ACID 埋込 KV: dedup index ミラー + pack table + stat-cache + shadow tree + resume journal。mmap-backed、RSS 有界、pure-Rust |
| **(自作) fastcdc-keyed** | key-derived gear table の FastCDC v2020（~150行）。stock **fastcdc** はテストオラクル |
| **blake3** | keyed_hash（chunk/tree id + 整合性）、unkeyed（pack 名）、derive_key（subkey KDF）。SIMD |
| **xorf** | per-segment BinaryFuse8/16 membership filter（~9 bit/chunk、dedup-miss ホットパス） |
| **fastbloom** | live memtable 向け mutable Bloom |
| **dashmap** | 並行 memtable、pending-claim、hardlink coalescing、reorder buffer |
| **smallvec** | インライン小チャンクリスト（per-file heap alloc 回避） |
| **roaring** | prune mark phase の live-chunk bitmap、verify reachable-pack set |
| **zstd** | per-blob 圧縮（libzstd）、skip-if-incompressible、ZDICT 辞書 |
| **chacha20poly1305** | デフォルト AEAD = XChaCha20-Poly1305（192-bit ランダム nonce） |
| **aes-gcm** | 任意の AES-256-GCM（AES-NI ホスト、single-use key 派生） |
| **aes-gcm-siv** | 任意の misuse-resistant 代替 |
| **argon2** | passphrase → KEK（Argon2id RFC 9106） |
| **secrecy / zeroize / subtle** | 鍵素材の SecretBox・zero-on-drop・constant-time 比較 |
| **getrandom / rand_core(OsRng)** | per-blob nonce/salt、master key、repo_id、Argon2 salt の CSPRNG |
| **rpassword / keyring** | TTY no-echo prompt / OS keyring（feature-gated） |
| **ciborium** | trees/snapshots/header/config/index の決定論的 CBOR |
| **rmp-serde / serde** | index header・pack table・stat-cache・KeyFile の msgpack シリアライズ |
| **object_store** | S3/GCS/Azure/MinIO/Ceph/HTTP/local 統一 trait（PutMode::Create、get_ranges、put_multipart） |
| **aws-sdk-s3** | Object Lock/WORM、RestoreObject、storage-class 遷移 |
| **reed-solomon-simd** | 任意の erasure coding parity（verify --repair） |
| **bytes** | ゼロコピー refcounted バッファ（chunk→seal→pack→upload→restore） |
| **flume** | bounded MPMC channel（rayon↔tokio 橋渡し、両端 sync/async、backpressure） |
| **tokio / tokio-util** | async runtime、Semaphore、signal、CancellationToken |
| **rayon** | data-parallel sub-task（oversized chunk hash、verify/restore fan-out） |
| **backoff** | exponential backoff with jitter（upload retry） |
| **moka** | restore 時の復号済み共有 blob LRU |
| **clap (derive) / clap_complete / clap_mangen** | コマンドサーフェス、completion、man |
| **figment / toml / serde_json** | 層状 config、TOML、JSON/NDJSON 出力 |
| **etcetera** | XDG/プラットフォーム config/cache dir 解決 |
| **indicatif / tracing / tracing-subscriber / tracing-indicatif** | 進捗バー、構造化ログ、log/bar 調停 |
| **console / owo-colors / comfy-table** | TTY 検出、色制御、整列テーブル |
| **globset** | include/exclude glob（backup + selective restore） |
| **jiff / bytesize** | duration/サイズの parse/format、retention 時刻計算 |
| **filetime / xattr / nix** | mtime 設定、xattr、特殊ファイル restore |
| **tar** | `dump` の tar ストリーム |
| **fuser** | 任意の read-only FUSE mount（feature `mount`） |
| **thiserror / anyhow** | typed エラー（lib）/ anyhow（CLI edge） |
| **proptest (+ state-machine) / cargo-fuzz / libfuzzer-sys / arbitrary** | property/モデルベース/ファジング |
| **assert_cmd / predicates / insta / tempfile** | CLI e2e、snapshot テスト |
| **testcontainers** | MinIO レーン（実 S3 multipart/range/consistency） |
| **criterion / cargo-nextest / cargo-llvm-cov / cargo-deny / cargo-audit** | bench、runner、coverage、supply-chain 監査 |
| **rand / rand_chacha** | 決定論的 pack サンプリング、テスト用 seeded RNG |
| **crossbeam-utils** | CachePadded（Metrics atomics の false sharing 回避） |

---

## 11. 実装ロードマップ

各マイルストーンは**それ自身でデモ可能**であり、後続が前の不変条件を破らないよう設計する。

> **実装状況（現行を正とするのは README の Roadmap）**: 本節は週見積もり付きの当初計画。
> M0–M5 は実質的に出荷済み — FastCDC dedup、zstd（skip-if-incompressible、`init --compression`）、
> Argon2id/XChaCha20-Poly1305、keyed-BLAKE3 id、S3 系オブジェクトストア、`verify`/`verify --sample`/`check`、
> `forget`/`prune`、複数パスフレーズ。M1 の特殊ファイル（FIFO/デバイス/ハードリンク/sparse）、
> メモリ有界ストリーミング backup/restore、オンディスク stat-cache（`backup --cache`、redb、
> `(dev,ino)→chunk-ids`、再利用はリポジトリ内 blob 存在で必ずゲート）、読み取り専用 FUSE mount
> （`sluice mount`、任意 `fuse` feature、libfuse リンク）も完了。**未実装の主項目**:
> 真の並列バックアップパイプライン（現状 verify/restore の読み出しのみ並列）、
> Windows メタデータ、Reed-Solomon self-heal（`verify --repair`）、辞書圧縮。

### M0 — Skeleton（~1-2週）
- Cargo workspace 構築（§4 のクレート/モジュール骨格）。
- `sluice-core`: `Id`/`ChunkId`/`PackId`/`BlobKind`/`Location`/`EntryKind` と CBOR canonical profile、エラー型。
- `StorageBackend` trait 定義 + `MemoryBackend`（テスト用 in-memory）+ `LocalBackend`（tmp+fsync+rename+fsync(dir)）。
- clap コマンドツリーのスタブ（`init`/`backup`/`restore`/`snapshots` がパースのみ）、`tracing` セットアップ。
- **デモ**: `sluice init /path` が config + key オブジェクトを書ける（暗号化は後続だが形式は確定）。

### M1 — MVP: ローカル backup + restore（~3-4週）
- `sluice-scan` の最小版（`ignore::WalkParallel`、stat、shadow tree、CBOR tree 組立）。
- 固定サイズチャンク（CDC は M2）で blob 化、pack 組立、`LocalBackend` へ書き込み、Snapshot 最後書き。
- `restore`: tree DAG walk → pack range-GET → ファイル書き込み → メタデータ replay（mode/mtime/symlink）。
- `snapshots` / `ls` 表示。**暗号化・圧縮・dedup はまだ無し**（plaintext pack）。
- **デモ**: ローカルディレクトリを backup → restore して**バイト一致**を proptest で検証。クラッシュ整合性の最初のテスト（snapshot 未書き込み = 整合）。

### M2 — Dedup + Compression（~3-4週）
- `sluice-chunk`: 自作 FastCDC v2020（最初は public gear、key-derived は M3）。property/vector テスト（境界シフト不変、サイズ分布）。
- `chunk_id = BLAKE3`（M3 で keyed 化）。
- `sluice-index`: memtable + redb cache + repo セグメント形式 + xorf filter + コンパクション + `rebuild-index`。
- 増分ゲート（stat-cache）、Unchanged バイパス、within-run get-or-reserve。
- `sluice-crypto` の zstd 統合（skip-if-incompressible）。
- **デモ**: 同一データ再 backup が**ほぼゼロ新規格納**。2回目が並列 stat ウォークに収束。

### M3 — Encryption（~3-4週）
- `sluice-crypto` 完成: Argon2id KEK、master wrap/unwrap、`derive_key` subkey、`BlobCrypto` 単一 seal/open 経路（AAD 集中、property テスト）。
- XChaCha20-Poly1305 デフォルト、AES-256-GCM（single-use key）任意。
- **key-derived gear** へ移行（境界秘匿）。chunk_id を **keyed BLAKE3** へ。
- config/key/index/pack-footer の AEAD 封緘、`head`（anti-rollback）。
- `key add|passwd|list|remove`、`secrecy`/`zeroize` 衛生、core-dump 無効化。
- 暗号 KAT（Argon2id wrap、AEAD、derive）golden ベクタ。
- **デモ**: untrusted backend が暗号文のみ見る。passphrase ローテーション O(1)。fuzz ターゲット（decrypt-garbage は clean error）。

### M4 — オブジェクトストレージ / オフサイト DR（~3-4週）
- `ObjectStoreBackend<T>`（S3/MinIO/GCS/Azure）: PutMode::Create、get_ranges、put_multipart。
- `sluice-engine` の rayon/tokio パイプライン本格化: flume bounded channel、backpressure、upload semaphore、`--memory-limit` 導出、cancel/resume。
- multipart abort、orphan sweep、lifecycle ルール案内。
- `S3WormBackend`（aws-sdk-s3）: Object Lock/WORM、`ColdTier`（RestoreObject + poll）、restore planner の tier 対応。
- **デモ**: S3 へ backup/restore（testcontainers MinIO レーン）。millions-of-files 合成コーパスで**ピーク RSS が cap 以下**を検証。

### M5 — prune/GC/verify（~3-4週）
- `verify`: 構造（roaring）→ presence → `--read-data` → `--read-data-subset`（seeded サンプリング）。破損→ファイル逆引きレポート。
- `forget`（retention bucketing）と `prune`（mark-sweep + repack-by-copy + segment compaction）を**分離**。exclusive prune lock、grace period、dry-run plan。
- 任意の Reed-Solomon erasure（`verify --repair`）。
- **モデルベース proptest**（最高価値テスト）: ランダム op 列で「全 snapshot がビット一致リストア / prune が live を消さない / verify が常に pass」を assert。
- **デモ**: 保持ポリシー運用、prune 後も全 live データ復元可。`FaultBackend` でクラッシュ整合性の sweep テスト。

### M6 — 性能 + クロスプラットフォーム仕上げ（~3-4週）
- `criterion` bench（CDC/BLAKE3/zstd/encrypt/index/end-to-end）、core_affinity ピン留め、bandwidth limit（token bucket）。
- `MetadataProvider` trait の Windows 実装（NTFS FileId、ADS/ACL）、capability-probe + warn。
- 任意の FUSE mount（`fuser`）、`diff`、`stats`、`dump`、completions/man。
- golden format テスト、interop（前リリースバイナリのリポジトリを restore）、CI matrix（Linux/macOS/Windows、stable+MSRV、clippy -D warnings、cargo-deny/audit、llvm-cov）。
- size-bucket padding（high-threat 任意）、metrics エクスポート（Prometheus textfile）。
- **デモ**: 性能回帰ゲート付き CI、3 プラットフォームで動作、フォーマット安定性保証。

---

## 12. 主要リスクと対策

| リスク | 対策 |
|---|---|
| **prune/GC が最高リスクコード**（1バグで live データ削除） | 厳格な「追記→削除」順序、grace period、dry-run plan 出力、backup-lock 中は拒否、モデルベース/フォールトインジェクションの徹底テスト |
| **stat ベース変更検出の盲点**（size/mtime/ctime/inode 保存の in-place 編集を Unchanged 扱い） | ctime+inode で窓を near-adversarial に縮小、`--read-all`/`--force` と `rehash-after` で paranoid 向けに閉じる |
| **chunk_id 衝突 → 偽 dedup → サイレントデータ消失** | BLAKE3 birthday ~2^-128 で無視可、加えて dedup hit 毎に length 等価ガード（不一致なら衝突/バグ扱いで再格納+警告） |
| **filter RAM が数十億で ~1GB** | hard budget + sheddable（超過時は redb-only に劣化、OOM しない）、avg chunk size を 4-8 MiB に上げて chunk 数削減、sharded filter |
| **untrusted-repo パーサが主攻撃面**（malicious pack/index/tree/snapshot/config が panic/OOB/無限ループ/巨大 alloc） | decoder 毎の cargo-fuzz ターゲット、**確保前に全 length フィールドを cap**、reject-before-allocate、fuzz build に ASan |
| **CSPRNG 失敗**（VM snapshot/clone 再利用、早期 boot 低エントロピー）で nonce/master 衝突 | XChaCha 192-bit nonce マージン + AES 経路の per-blob key 派生、getrandom health check、VM テンプレートリポジトリは鍵再 init |
| **rayon/tokio デッドロック**（CPU task 内 block_on、tokio worker 上の CPU work） | 厳格なプール分離、CPU ステージに async ゼロ、CI lint/レビューで境界監視 |
| **ローカル redb キャッシュの破損/乖離** | 純キャッシュ扱い、segment からの安価な rebuild と pack-footer からの深い rebuild、決して真実源にしない、repo_id+format version+clock-sanity で invalidate |
| **WORM 誤設定**（過長 COMPLIANCE retention でリポジトリが prune 不能・コスト膨張） | guardrail、GOVERNANCE vs COMPLIANCE の明確な UX、有効化前のコスト見積もり、retention >= backup cadence の強制 |
| **S3 弱整合性ストア** が commit 順序/orphan 検出の前提を崩す | 保守的 grace period、任意の HEAD-after-PUT 検証（AWS S3 本体は 2020年以降 strong consistency） |
| **CBOR canonical エンコードドリフト**で tree/snapshot id がずれ dedup/DAG 検証を破壊 | canonical profile をピン、チェックインしたテストベクタ、再生成は format-version bump + レビュー必須 |
| **マルチパート abort/orphan pack** がサイレントにコスト累積 | lifecycle auto-abort ルール + prune の orphan-sweep |
| **cold-tier thaw 遅延**（分〜時）が restore RTO を膨張 | restore planner を tier-aware に（RestoreObject 発行 → poll → park）、thaw ETA 表示 |
| **秘密漏洩経路**（argv、ログ、swap、core dump） | `--password <value>` 不採用、SecretString+zeroize、tracing redact、core-dump 無効化+任意 mlock |

---

## 13. テスト・信頼性戦略

決定論を可能にする **seam**: `StorageBackend` trait（in-memory + FaultBackend 実装）、retention 用の注入可能 `Clock`、nonce/サンプリング用の test-only seeded RNG（production は OsRng ハードワイヤ）。

### ユニット
純粋関数: CDC 境界、glob matcher、retention bucketing、セレクタ解決、サイズ/duration parse、config precedence。

### Property（proptest）
- **バイトストリーム roundtrip**: chunk→compress→encrypt→pack→index→restore が恒等。
- **CDC**: 決定論 + min/max 境界 + edit-locality（挿入/削除が O(1) チャンクのみシフト）。
- **CBOR tree roundtrip**: メタデータ完全忠実（mode/times/xattr/hardlink/特殊ファイル）。
- retention が正確に文書化された集合を keep。config precedence が total order。restore overwrite 状態機械。

### 最高価値テスト — モデルベースエンジンテスト（proptest-state-machine）
モデル = `BTreeMap<ChunkId, Bytes>` + snapshot set。in-memory `object_store` 上でランダム op 列（合成 FS tree の backup、forget、prune、restore、verify）を適用し**不変条件**を assert: 全 snapshot が**ビット一致**リストア、prune は live chunk を決して消さない、well-formed repo で verify が常に pass。ランダム FS tree ジェネレータ（proptest → `tempfile::TempDir`）が空ファイル/dir、巨大/sparse ファイル、unicode/奇妙な名前、深いネスト、symlink/hardlink、perm bit、mid-backup 変異をカバー、深い content+metadata 木等価で assert。

### Fuzzing（cargo-fuzz + libfuzzer-sys + arbitrary）
untrusted-input decoder 毎に1ターゲット（pack header、index segment、tree CBOR、snapshot、config）に malformed/truncated/adversarial バイトを投入 → **panic/OOB/hang/over-allocate 厳禁**（length フィールドは確保前に cap）、clean error のみ。加えて decrypt-garbage（clean AEAD 失敗）と structure-aware encode→decode→equal ターゲット。corpus を保持し継続実行、nightly で fuzz + mmap unsafe パスに ASan。

### クラッシュ整合性 / フォールトインジェクション
`FaultBackend<B>` decorator が N 番目の op を fail/drop/truncate/reorder/delay。backup を駆動し op N で abort（範囲 sweep）→ repo が open でき、verify が pass、**以前コミットされた全 snapshot がリストア可、中断 snapshot は単に不在**（snapshot-written-last 不変）、resume が orphan に対し dedup。`LocalBackend` の fsync 順序（tmp+rename+dir-fsync）を write-log replay で任意プレフィックス検証。

### プロセスレベル（assert_cmd）
実バイナリを spawn、seed sweep で backup 途中に SIGKILL → reopen+verify+restore。**2つの並行 `backup` プロセスが両方成功**し破損なし。`prune` は backup lock 存在中は拒否。

### Golden フォーマットテスト
**FROZEN フォーマットバージョン**からのチェックイン小リファレンスリポジトリ + hex シリアライズベクタ（CBOR/msgpack）+ 暗号 KAT（Argon2id wrap、AEAD、keyed-BLAKE3 derive）でオンディスク/ワイヤ安定性を guard。`insta` で CLI text/JSON/`--help`/`ls`/`diff` 出力をピン。nightly で**前リリースバイナリ作成リポジトリを restore**（interop）。**ベクタ変更は format-version bump + reviewer サインオフ必須**、CI ガードが bump なしのベクタ変更で fail。

### CLI e2e / バックエンド2レーン
`assert_cmd`+`predicates`+`tempfile`+`insta` でフルライフサイクル（init→backup→snapshots→ls→diff→restore→verify→forget→prune）。**in-memory object_store レーン**（高速・決定論）と **MinIO/testcontainers レーン**（実 S3 multipart/range/consistency）。

### 有界メモリテスト
millions-of-files 合成コーパスを backup し**ピーク RSS（VmHWM）が cap 以下**を assert — ハード要件を直接行使。

### 性能 / CI matrix
`criterion` bench（CDC/BLAKE3/zstd/encrypt/index/end-to-end）で回帰追跡。CI: Linux/macOS/Windows、stable+MSRV、`clippy -D warnings`、`fmt --check`、`cargo-deny`+`cargo-audit`（暗号依存に critical な supply-chain/advisory）、`cargo-llvm-cov`、`cargo-nextest`、pure-logic/unsafe に `miri`。nightly（fuzz/ASan/miri/モデルベース）を stable ship build から隔離。