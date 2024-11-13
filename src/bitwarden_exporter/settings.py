"""
This module provides functionality to manage settings for the Bitwarden Exporter.

Classes:
    BitwardenExportSettings: A Pydantic model that defines the settings for the Bitwarden Exporter.

Functions:
    get_bitwarden_settings_based_on_args: Parses command-line arguments to populate
      and return a BitwardenExportSettings instance.

The settings include:
    - export_location: The location where the Bitwarden export will be saved.
    - export_password: The password used for the Bitwarden export.
    - allow_duplicates: A flag to allow duplicate entries in the export.
    - tmp_dir: The temporary directory to store sensitive files during the export process.
    - verbose: A flag to enable verbose logging, which may include sensitive information.
"""

import argparse
import os
import time

import pyfiglet  # type: ignore
from pydantic import BaseModel


class BitwardenExportSettings(BaseModel):
    """
    Settings Model
    """

    export_location: str
    export_password: str
    allow_duplicates: bool
    tmp_dir: str
    verbose: bool


def get_bitwarden_settings_based_on_args() -> BitwardenExportSettings:
    """
    Manage Input Arguments for Bitwarden Exporter
    """

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-l",
        "--export-location",
        help="Bitwarden Export Location, Default: bitwarden_dump_<timestamp>.kdbx, This is a dynamic value,"
        " Just in case if it exists, it will be overwritten",
        default=f"bitwarden_dump_{int(time.time())}.kdbx",
    )

    parser.add_argument(
        "-p",
        "--export-password",
        help="Bitwarden Export Password, It is recommended to use a password file",
        required=False,
    )

    parser.add_argument(
        "-pf",
        "--export-password-file",
        help="Bitwarden Export Password File, Mutually Exclusive with --export-password",
        required=False,
    )

    parser.add_argument(
        "--allow-duplicates",
        help="Allow Duplicates entries in Export, In bitwarden each item can be in multiple collections,"
        " Default: --no-allow-duplicates",
        action=argparse.BooleanOptionalAction,
        default=False,
    )

    parser.add_argument(
        "--tmp-dir",
        help="Temporary Directory to store temporary sensitive files,"
        " Make sure to delete it after the export,"
        f" Default: {os.path.abspath('bitwarden_dump_attachments')}",
        default=os.path.abspath("bitwarden_dump_attachments"),
    )

    parser.add_argument(
        "--verbose",
        help="Enable Verbose Logging, This will print debug logs, THAT MAY CONTAIN SENSITIVE INFORMATION,"
        " Default: --no-verbose",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    print(pyfiglet.figlet_format("Bitwarden Exporter"))
    args = parser.parse_args()

    if args.export_password is None and args.export_password_file is None:
        parser.error("Please provide either --export-password or --export-password-file")

    if args.export_password is not None and args.export_password_file is not None:
        parser.error("Please provide either --export-password or --export-password-file, not both")

    if args.export_password_file is not None:
        with open(args.export_password_file, "r", encoding="utf-8") as file:
            args.export_password = file.read().strip()

    return BitwardenExportSettings(
        export_location=args.export_location,
        export_password=args.export_password,
        allow_duplicates=args.allow_duplicates,
        tmp_dir=args.tmp_dir,
        verbose=args.verbose,
    )
