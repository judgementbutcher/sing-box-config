# sing-box-config

This repository contains a local configuration generator for
[sing-box](https://sing-box.sagernet.org/). It is intended to keep the
automation code, parsers, and sanitized example files under version control.

The public repository intentionally does not include personal routing rules,
subscription provider names, subscription URLs, node credentials, generated
runtime configs, logs, caches, or local binaries.

## Contents

- `build_singbox.py`: generates a sing-box config from a template and a
  subscription manifest.
- `parsers/`: parsers for common proxy subscription formats.
- `template.example.json`: sanitized sing-box template for public reference.
- `subscriptions.example.yaml`: sanitized subscription manifest example.
- `reload.bat`: local Windows helper for generating, checking, and restarting.

## Local Files

Create local private files from the examples:

```powershell
Copy-Item .\template.example.json .\template.json
Copy-Item .\subscriptions.example.yaml .\subscriptions.yaml
```

Local-only files are ignored by git:

- `README.local.md`
- `template.json`
- `subscriptions.yaml`
- `config.json`
- `config.next.json`
- `nodes-report.json`
- `subscriptions/`
- `.subscription-cache/`
- `logs/`
- `backups/`
- runtime binaries and downloaded archives

Do not commit generated configs or subscription files. They can contain
subscription URLs, node credentials, custom domains, and other private data.

## Usage

Generate a config:

```powershell
python .\build_singbox.py --template .\template.json --output .\config.json
```

Check the config:

```powershell
.\sing-box.exe check -c .\config.json
```

Use the reload helper on Windows:

```bat
reload.bat
```

## sing-box 1.14 Notes

The sanitized example follows the sing-box 1.14 configuration style:

- Remote rule-set downloads use `http_client`.
- `route.default_http_client` is configured explicitly.
- Deprecated `download_detour` and `dns.independent_cache` are not used.

Official references:

- https://github.com/SagerNet/sing-box/releases/tag/v1.14.0-alpha.39
- https://sing-box.sagernet.org/deprecated/
- https://sing-box.sagernet.org/configuration/
- https://sing-box.sagernet.org/configuration/route/
- https://sing-box.sagernet.org/configuration/shared/http-client/
