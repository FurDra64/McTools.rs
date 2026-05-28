# mctools

**Rust port of McTools — Encrypt and decrypt Minecraft Bedrock marketplace content.**

Originally a C# toolset by [Li (LiEnby)](https://github.com/LiEnby),
rewritten in Rust for cross-platform use.

This repository was created using OpenCode VibeCoding.

`index.html`, `mctools_bg.wasm`, `mctools_wasm.js` were made for GitHub Pages
to encrypt skins for iOS.

Japanese version: [README-JP.md](README-JP.md)

## Build

```bash
cargo build --release
```

## Configuration

See `mctools.cfg` in the repository root.  The config file format follows the
original C# McTools — `KEY: value` lines, with variable substitution:

| Variable           | Resolves to                         |
|--------------------|-------------------------------------|
| `$APPDATA`         | `~/.AppData/Roaming` (Linux default)|
| `$LOCALAPPDATA`    | `~/.local/share` (Linux default)    |
| `$TEMP`            | `/tmp` (Linux default)              |
| `$MCDIR`           | Minecraft folder                    |
| `$CACHEDIR`        | Cache folder                        |
| `$EXECDIR`         | Executable directory                |
| `$USERSDIR`        | Users directory                     |
| `$PREMIUMCACHE`    | Premium cache                       |
| `$SERVERPACKCACHE` | Server pack cache                   |
| `$REALMSPREMIUMCACHE` | Realm premium cache             |
| `$OUTFOLDER`       | Output folder                       |

Key options:

- `CrackThePacks: yes/no` — Remove encryption markers from world/skin data
- `ZipThePacks: yes/no` — Repack decrypted output into `.mcpack` / `.mcworld` etc.
- `MultiThread: yes/no` — Enable multi-threaded processing
- `DecryptExistingWorlds: yes/no` — Scan already-installed worlds
- `KeysDb: <path>` — Path to `keys.db` (friendlyId=contentKey pairs)

---

## License

**Unlicense** — This project is dedicated to the public domain.
See `UNLICENSE` for details.

> **Note:** The original C# McTools toolset by [Li (LiEnby)](https://github.com/LiEnby)
> was distributed without a license.  This Rust port is an independent
> reimplementation.  See `NOTICE` for attribution and legal context.
