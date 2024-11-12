"""
This module provides a command-line interface (CLI) for interacting with Bitwarden.

Functions:
    bw_exec(cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None) -> str:

Exceptions:
    BitwardenException:
        Raised when there is an error executing a Bitwarden CLI command.
"""

import logging
import os
import os.path
import subprocess  # nosec B404
import tempfile
from typing import Dict, List, Optional

from cachier import cachier

from . import BitwardenException

LOGGER = logging.getLogger(__name__)


@cachier()
def download_file(item_id: str, attachment_id: str) -> str:
    """
    Downloads a file from bitwarden.
    """
    with tempfile.NamedTemporaryFile(delete=False) as attachment_path:
        out = bw_exec(
            ["get", "attachment", attachment_id, "--itemid", item_id, "--output", attachment_path.name], is_raw=False
        )
        LOGGER.info("Downloaded attachment %s, %s", attachment_id, out)
        return attachment_path.name


@cachier()
def bw_exec(
    cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None, is_raw: bool = True
) -> str:
    """
    Executes a Bitwarden CLI command and returns the output as a string.
    """
    cmd = ["bw"] + cmd

    if is_raw:
        cmd.append("--raw")

    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)
    LOGGER.debug(f"Executing CLI :: {' '.join(cmd)}")
    command_out = subprocess.run(
        cmd, capture_output=True, check=False, encoding=ret_encoding, env=cli_env_vars
    )  # nosec B603
    if len(command_out.stderr) > 0:
        raise BitwardenException(f"Error in executing command {command_out.stderr}")
    command_out.check_returncode()
    if len(command_out.stdout) > 0:
        return command_out.stdout

    return ""
