"""
Writes the given data to a file at the specified path.
"""

import logging
import time
from typing import Union

from pykeepass import PyKeePass, create_database

from . import BitwardenException

LOGGER = logging.getLogger(__name__)


def write_to_file(data: str, path: Union[str, bytes]) -> None:
    """
    Function to write to a file.
    """
    if isinstance(data, str):
        mode = "w"
        sys_encoding = "UTF-8"
    elif isinstance(data, bytes):
        mode = "wb"
        sys_encoding = None
    else:
        raise BitwardenException("Type Unable to Write {type(data)}")

    with open(path, mode, encoding=sys_encoding) as file_attach:
        file_attach.write(data)


def write_to_keepass() -> None:
    """
    Function to write to Keepass
    """
    epoch_time = int(time.time())
    file_name = f"bitwarden_dump_{epoch_time}.kdbx"
    LOGGER.info("Creating Keepass Database: %s, Password: password", file_name)
    kp = create_database(file_name, password="password")
    print(kp.root_group)
