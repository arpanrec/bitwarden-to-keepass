# Bitwarden export migrate

Python Wrapper for bitwarden cli dump with **attachments**.

This allows you to take a whole backup of your bitwarden vault, including organizations where you don't have access for admin/owner. And fully compatible with bitwarden import `bw import <format> <path>`.

## Prerequisites

- [Bitwarden CLI](https://bitwarden.com/help/article/cli/#download-and-install)
- [Python3](https://www.python.org/downloads/)
- [PIP](https://pip.pypa.io/en/stable/)
- Gnupg (Optional only for encrypted exports) Most of the Mac and Linux System will have it preinstalled. [For Windows](https://www.gpg4win.org)

## Instructions

```bash
$ python3 -m pip install -r requirements.txt 
Requirement already satisfied: python-gnupg in ./venv/lib/python3.9/site-packages (from -r requirements.txt (line 1)) (0.4.7)
Requirement already satisfied: configargparse in ./venv/lib/python3.9/site-packages (from -r requirements.txt (line 2)) (1.5.3)
$ python3 bw_dump.py
```

- `-d` `--directory`  
    (String) Bitwarden Dump Location.  
    Default: `dump_time`

- `-g` `--gpg-fpr`  
    (String) gpg-key-id for file encryption. Public key must be uploaded to [keyserver](hkps://keys.openpgp.org)  
    Default: `None`

## Roadmap

Make a cloud ready option for bitwarden zero touch backup

- Upload to GDrive / PCloud / Onedrive.
- Create Encrypted zip instate of encrypt each individual file.
- Support for bitwarden official export method `bw export <masterpassword> --organizationid` on demand.
- Jenkins Integration for credential delivery
- Export to KDBX4 based file

## Credits

[@ckabalan](https://github.com/ckabalan) for [bitwarden-attachment-exporter](https://github.com/ckabalan/bitwarden-attachment-exporter)

## License

MIT
