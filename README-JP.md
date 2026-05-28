# mctools

**McTools の Rust 移植版 — Minecraft Bedrock マーケットプレイスコンテンツの暗号化・復号ツール**
 
元は [Li (LiEnby)](https://github.com/LiEnby) による C# ツール群。  
クロスプラットフォーム対応のため Rust で書き直しました。

このリポジトリはOpenCodeを使用してVibe Codingしました。

`index.html`, `mctools_bg.wasm`, `mctools_wasm.js`はGithub PagesでiOS用にSkinを暗号化する為に作成されました。

## Build

```bash
cargo build --release
```

## 設定

リポジトリルートの `mctools.cfg` を参照。設定ファイルの書式はオリジナルの C# McTools
に準拠しています — `KEY: value` 形式で、変数展開に対応:

| Variable / 変数  | Resolves to / 展開先                         |
|------------------|----------------------------------------------|
| `$APPDATA`       | `~/.AppData/Roaming` (Linux デフォルト) |
| `$LOCALAPPDATA`  | `~/.local/share` (Linux デフォルト)    |
| `$TEMP`          | `/tmp` (Linux デフォルト)               |
| `$MCDIR`         | Minecraft フォルダ          |
| `$CACHEDIR`      | キャッシュフォルダ              |
| `$EXECDIR`       | 実行ファイルのあるディレクトリ    |
| `$USERSDIR`      | ユーザーディレクトリ            |
| `$PREMIUMCACHE`  | プレミアムキャッシュ            |
| `$SERVERPACKCACHE` | サーバーパックキャッシュ      |
| `$REALMSPREMIUMCACHE` | Realm プレミアムキャッシュ |
| `$OUTFOLDER`     | 出力フォルダ                   |

主な設定項目:

- `CrackThePacks: yes/no` — ワールド・スキンデータから暗号化マーカーを除去
- `ZipThePacks: yes/no` — 復号結果を `.mcpack` / `.mcworld` 等に再パッケージ
- `MultiThread: yes/no` — マルチスレッド処理を有効化
- `DecryptExistingWorlds: yes/no` — 既存のインストール済みワールドもスキャン対象に含める
- `KeysDb: <path>` — `keys.db` のパス（friendlyId=contentKey のペア）

---

## License / ライセンス

**Unlicense** — このプロジェクトはパブリックドメインに献呈されています。
詳細は `UNLICENSE` を参照してください。

> **注意:** [Li (LiEnby)](https://github.com/LiEnby) によるオリジナルの C# McTools ツール群は
> ライセンスなしで配布されています。この Rust 移植版は独立した再実装です。
> 著作権表示と法的な文脈については `NOTICE` を参照してください。
