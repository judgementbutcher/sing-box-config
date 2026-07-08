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
- `templates/`: local sing-box templates named by platform/version.
- `template.example.json`: sanitized sing-box template for public reference.
- `subscriptions.example.yaml`: sanitized subscription manifest example.
- `reload.bat`: local Windows helper for generating, checking, and restarting.
- `build_android.bat`: local Windows helper for generating Android config.

## Local Files

Create local private files from the examples:

```powershell
New-Item -ItemType Directory -Force .\templates
Copy-Item .\template.example.json .\templates\desktop-windows-sing-box-1.14.json
Copy-Item .\subscriptions.example.yaml .\subscriptions.yaml
```

Local-only files are ignored by git:

- `README.local.md`
- `template.json`
- `templates/*.json`
- `subscriptions.yaml`
- `config.json`
- `config.next.json`
- `config.*.json`
- `nodes-report.json`
- `nodes-report*.json`
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
python .\build_singbox.py --output .\config.json
```

Without `--template`, the script lists `templates/*.json` and asks which
template to use. To bypass the prompt, pass the template explicitly:

```powershell
python .\build_singbox.py --template .\templates\desktop-windows-sing-box-1.14.json --output .\config.json
```

Generate a config and keep subscription info entries in their provider groups:

```powershell
python .\build_singbox.py --template .\templates\desktop-windows-sing-box-1.14.json --output .\config.json --keep-info-nodes
```

When the provider returns a `Subscription-Userinfo` response header, the
generated `nodes-report.json` includes `subscription_userinfo` with upload,
download, total, remaining traffic, and expiration fields.

Check the config:

```powershell
.\sing-box.exe check -c .\config.json
```

Use the reload helper on Windows:

```bat
reload.bat
```

`reload.bat` is pinned to `templates\desktop-windows-sing-box-1.14.json`
because it checks and restarts the local Windows sing-box service.

## Android

The Android template is `templates\mobile-android-sing-box-1.13.14.json`.
Generate a phone config on the PC:

```bat
build_android.bat
```

Manual equivalent:

```powershell
python .\build_singbox.py --template .\templates\mobile-android-sing-box-1.13.14.json --output .\config.android.json --report .\nodes-report.android.json --keep-info-nodes
```

Then import `config.android.json` into the Android sing-box app. The phone does
not need to run this Python generator in normal use; rerun the generator on the
PC when subscriptions or rules change, then replace the config on the phone.

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
