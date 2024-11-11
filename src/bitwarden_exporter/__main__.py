#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os.path
import subprocess  # nosec B404
import time
from typing import Any, Dict, List, Optional

from . import BitwardenException
from .models import BwCollection, BwFolder, BwItem, BwOrganization

LOGGER = logging.getLogger(__name__)


def bw_exec(cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None) -> str:
    cmd = ["bw"] + cmd + ["--raw"]

    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)
    print(f"Executing CLI :: {' '.join(cmd)}")
    command_out = subprocess.run(
        cmd, capture_output=True, check=False, encoding=ret_encoding, env=cli_env_vars
    )  # nosec B603
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
        raise BitwardenException("Vault is not unlocked")

    # Fetch Organization Details
    bw_organizations_dict = json.loads((bw_exec(["list", "organizations"])))
    # {"id", BwOrganization}
    bw_organizations: Dict[str, BwOrganization] = {
        organization["id"]: BwOrganization(**organization) for organization in bw_organizations_dict
    }
    logging.info("Total Organizations Fetched: %s", len(bw_organizations))

    bw_collections_dict = json.loads((bw_exec(["list", "collections"])))
    logging.info("Total Collections Fetched: %s", len(bw_collections_dict))

    for bw_collection_dict in bw_collections_dict:
        bw_collection = BwCollection(**bw_collection_dict)
        organization = bw_organizations[bw_collection.organizationId]
        organization.collections[bw_collection.id] = bw_collection

    # Fetch Organization Details
    bw_items_dict: List[Dict[str, Any]] = json.loads((bw_exec(["list", "items"])))
    logging.info("Total Items Fetched: %s", len(bw_items_dict))
    for bw_item_dict in bw_items_dict:
        bw_item = BwItem(**bw_item_dict)
        if not bw_item.organizationId:
            continue

        organization = bw_organizations[bw_item.organizationId]

        if not bw_item.collectionIds or len(bw_item.collectionIds) < 1:
            raise BitwardenException(f"Item {bw_item.id} does not have any collection, but belongs to an organization")

        if len(bw_item.collectionIds) > 1:
            logging.warning(
                "Item %s belongs to multiple collections Just using the first one %s",
                bw_item.id,
                bw_item.collectionIds[0],
            )
        organization.collections[bw_item.collectionIds[0]].items[bw_item.id] = bw_item

        # for collection_id in bw_item.collectionIds:
        #     collection = organization.collections[collection_id]
        #     collection.items[bw_item.id] = bw_item

    logging.info("Total Items Fetched: %s", bw_organizations)

    bw_folders: List[BwFolder] = [BwFolder(**folder) for folder in json.loads((bw_exec(["list", "folders"])))]
    logging.info("Total Folders Fetched: %s", len(bw_folders))


if __name__ == "__main__":
    main()
