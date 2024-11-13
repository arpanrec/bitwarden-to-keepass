# Bitwarden Exporter

```text
 ____  _ _                         _            
| __ )(_) |___      ____ _ _ __ __| | ___ _ __  
|  _ \| | __\ \ /\ / / _` | '__/ _` |/ _ \ '_ \ 
| |_) | | |_ \ V  V / (_| | | | (_| |  __/ | | |
|____/|_|\__| \_/\_/ \__,_|_|  \__,_|\___|_| |_|
                                                
 _____                       _            
| ____|_  ___ __   ___  _ __| |_ ___ _ __ 
|  _| \ \/ / '_ \ / _ \| '__| __/ _ \ '__|
| |___ >  <| |_) | (_) | |  | ||  __/ |   
|_____/_/\_\ .__/ \___/|_|   \__\___|_|   
```

Python Wrapper for [Password Manager CLI](https://bitwarden.com/help/cli/) for exporting bitwarden vaults with **attachments**.

This allows you to take a whole backup of your bitwarden vault, including organizations where you don't have access for admin/owner.

## Prerequisites

- [Bitwarden CLI](https://bitwarden.com/help/article/cli/#download-and-install)
- [python-poetry](https://python-poetry.org/docs/#installation)

## Installation

Install with [pipx](https://github.com/pypa/pipx).

```bash
pipx install bitwarden-exporter
```

## Options

```bash
bitwarden-exporter --help
```

```text
  -h, --help            show this help message and exit
  -l EXPORT_LOCATION, --export-location EXPORT_LOCATION
                        Bitwarden Export Location, Default: bitwarden_dump_<timestamp>.kdbx, This is a dynamic value, Just in case if it exists, it will be overwritten
  -p EXPORT_PASSWORD, --export-password EXPORT_PASSWORD
                        Bitwarden Export Password, It is recommended to use a password file
  -pf EXPORT_PASSWORD_FILE, --export-password-file EXPORT_PASSWORD_FILE
                        Bitwarden Export Password File, Mutually Exclusive with --export-password
  --allow-duplicates, --no-allow-duplicates
                        Allow Duplicates entries in Export, In bitwarden each item can be in multiple collections, Default: --no-allow-duplicates
  --tmp-dir TMP_DIR     Temporary Directory to store temporary sensitive files, Make sure to delete it after the export, Default: /home/arpan/workspace/bitwarden-
                        exporter/bitwarden_dump_attachments
  --verbose, --no-verbose
                        Enable Verbose Logging, This will print debug logs, THAT MAY CONTAIN SENSITIVE INFORMATION, Default: --no-verbose
```

## Roadmap

Make a cloud ready option for bitwarden zero touch backup

- Upload to cloud storage.

## Credits

[@ckabalan](https://github.com/ckabalan) for [bitwarden-attachment-exporter](https://github.com/ckabalan/bitwarden-attachment-exporter)

## License

MIT
