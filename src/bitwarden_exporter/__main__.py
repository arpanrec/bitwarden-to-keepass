#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os.path
import subprocess
import time
from typing import Dict, List, Optional

from . import BitwardenException
from .models import BwCollection, BwFolder, BwItem, BwOrganization

LOGGER = logging.getLogger(__name__)


def bw_exec(cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None) -> str:
    cmd = ["bw"] + cmd + ["--raw"]

    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)
    print(f"Executing CLI :: {' '.join(cmd)}")
    command_out = subprocess.run(cmd, capture_output=True, check=False, encoding=ret_encoding, env=cli_env_vars)
    if len(command_out.stderr) > 0:
        raise BitwardenException(f"Error in executing command {command_out.stderr}")
    command_out.check_returncode()
    if len(command_out.stdout) > 0:
        return command_out.stdout

    return ""


def main() -> None:
    bw_current_status = json.loads(bw_exec(["status"]))

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--directory", help="Bitwarden Dump Location", default=f"bitwarden_dump_{int(time.time())}"
    )
    _, _ = parser.parse_known_args()

    if bw_current_status["status"] != "unlocked":
        raise BitwardenException("Unable to unlock the vault")

    # Fetch Organization Details
    bw_items: List[BwItem] = [BwItem(**item) for item in json.loads((bw_exec(["list", "items"])))]

    logging.info("Total Items Fetched: %s", len(bw_items))
    # Fetch Organization Details
    bw_organizations: List[BwOrganization] = [
        BwOrganization(**org) for org in json.loads((bw_exec(["list", "organizations"])))
    ]
    logging.info("Total Organizations Fetched: %s", len(bw_organizations))

    bw_collections: List[BwCollection] = [
        BwCollection(**collection) for collection in json.loads((bw_exec(["list", "collections"])))
    ]
    logging.info("Total Collections Fetched: %s", len(bw_collections))

    bw_folders: List[BwFolder] = [BwFolder(**folder) for folder in json.loads((bw_exec(["list", "folders"])))]
    logging.info("Total Folders Fetched: %s", len(bw_folders))


if __name__ == "__main__":
    main()
