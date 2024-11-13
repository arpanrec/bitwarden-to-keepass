"""
This module initializes logging for the Bitwarden Exporter application and defines a custom exception.

Classes:
    BitwardenException: Base exception for Bitwarden Export.
"""

import logging
import sys

from .settings import BitwardenExportSettings, get_bitwarden_settings_based_on_args

BITWARDEN_SETTINGS: BitwardenExportSettings = get_bitwarden_settings_based_on_args()

logging.basicConfig(
    level=logging.DEBUG if BITWARDEN_SETTINGS.verbose else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s.%(funcName)s():%(lineno)d:- %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


class BitwardenException(Exception):
    """
    Base Exception for Bitwarden Export
    """
