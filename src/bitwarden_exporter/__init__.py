"""
This module initializes logging for the Bitwarden Exporter application and defines a custom exception.

Classes:
    BitwardenException: Base exception for Bitwarden Export.
"""

import logging
import os
import sys


def is_debug() -> bool:
    """
    Function to check if debug is enabled.
    """

    enabled: bool = False
    if str(os.environ.get("DEBUG", "False")).lower() in ["true", "1", "yes"]:
        enabled = True
    return enabled


print("Remove existing log handlers")
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    level=logging.DEBUG if is_debug() else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s.%(funcName)s():%(lineno)d:- %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


class BitwardenException(Exception):
    """
    Base Exception for Bitwarden Export
    """
