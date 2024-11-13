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
from typing import Dict, List, Optional

LOGGER = logging.getLogger(__name__)


def download_file(item_id: str, attachment_id: str, download_location: str) -> None:
    """
    Downloads a file from bitwarden.
    """
    parent_dir = os.path.dirname(download_location)
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    if os.path.exists(download_location):
        LOGGER.info("File already exists, skipping download")
        return

    bw_exec(["get", "attachment", attachment_id, "--itemid", item_id, "--output", download_location], is_raw=False)


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
    LOGGER.debug("Executing CLI :: %s", {" ".join(cmd)})
    command_out = subprocess.run(
        cmd, capture_output=True, check=False, encoding=ret_encoding, env=cli_env_vars, timeout=10
    )  # nosec B603
    if len(command_out.stderr) > 0:
        LOGGER.warning("Error executing command %s", command_out.stderr)
    command_out.check_returncode()
    return command_out.stdout
