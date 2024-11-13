# Bitwarden Exporter

Python Wrapper for bitwarden cli dump with **attachments**.

This allows you to take a whole backup of your bitwarden vault, including organizations where you don't have access for admin/owner.

## Prerequisites

- [Bitwarden CLI](https://bitwarden.com/help/article/cli/#download-and-install)
- [python-poetry](https://python-poetry.org/docs/#installation)

## Instructions

```bash
git clone https://github.com/arpanrec/bitwarden-exporter.git
cd bitwarden-exporter
poetry install
poetry run bitwarden-exporter --help
```

- `-d` `--directory`  
    (String) Bitwarden Dump Location.  
    Default: `dump_time`

- `-g` `--gpg-fpr`  
    (String) gpg-key-id for file encryption. Public key must be uploaded to [keyserver](hkps://keys.openpgp.org)  
    Default: `None`

## Roadmap

Make a cloud ready option for bitwarden zero touch backup

- Upload to cloud storage.
- Create Encrypted zip instate of encrypt each individual file.

## Credits

[@ckabalan](https://github.com/ckabalan) for [bitwarden-attachment-exporter](https://github.com/ckabalan/bitwarden-attachment-exporter)

## License

MIT
