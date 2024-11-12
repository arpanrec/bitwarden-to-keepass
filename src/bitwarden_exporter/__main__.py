"""
This script interacts with the Bitwarden CLI to export data from a Bitwarden vault.

Functions:
    bw_exec(cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None) -> str:
        Executes a Bitwarden CLI command and returns the output as a string.
    
    main() -> None:
        Main function that handles the export process, including fetching organizations,
          collections, items, and folders from the Bitwarden vault.

Raises:
    BitwardenException: If there is an error executing a Bitwarden CLI command or if the vault is not unlocked.

"""

import argparse
import json
import logging
import time
from typing import Any, Dict, List

from . import BitwardenException
from .cli import bw_exec, download_file
from .models import BwCollection, BwFolder, BwItem, BwOrganization
from .write_to_file import write_to_keepass

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """
    Main function that handles the export process, including fetching organizations,
    """
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
    LOGGER.info("Total Organizations Fetched: %s", len(bw_organizations))

    bw_collections_dict = json.loads((bw_exec(["list", "collections"])))
    LOGGER.info("Total Collections Fetched: %s", len(bw_collections_dict))

    for bw_collection_dict in bw_collections_dict:
        bw_collection = BwCollection(**bw_collection_dict)
        organization = bw_organizations[bw_collection.organizationId]
        organization.collections[bw_collection.id] = bw_collection

    bw_items_dict: List[Dict[str, Any]] = json.loads((bw_exec(["list", "items"])))
    LOGGER.info("Total Items Fetched: %s", len(bw_items_dict))
    for bw_item_dict in bw_items_dict:
        LOGGER.debug("Processing Item %s", json.dumps(bw_item_dict))
        bw_item = BwItem(**bw_item_dict)
        LOGGER.info("Processing Item %s", bw_item.name)
        if bw_item.attachments and len(bw_item.attachments) > 0:
            LOGGER.info("Item %s has attachments %s", bw_item.id, bw_item.attachments)
            for attachment in bw_item.attachments:
                attachment.local_file_path = download_file(bw_item.id, attachment.id)
        if not bw_item.organizationId:
            continue

        organization = bw_organizations[bw_item.organizationId]

        if not bw_item.collectionIds or len(bw_item.collectionIds) < 1:
            raise BitwardenException(f"Item {bw_item.id} does not have any collection, but belongs to an organization")

        if len(bw_item.collectionIds) > 1:
            LOGGER.warning(
                "Item %s belongs to multiple collections Just using the first one %s",
                bw_item.id,
                bw_item.collectionIds[0],
            )
        organization.collections[bw_item.collectionIds[0]].items[bw_item.id] = bw_item

        # for collection_id in bw_item.collectionIds:
        #     collection = organization.collections[collection_id]
        #     collection.items[bw_item.id] = bw_item

    LOGGER.info("Total Items Fetched: %s", bw_organizations)

    bw_folders: List[BwFolder] = [BwFolder(**folder) for folder in json.loads((bw_exec(["list", "folders"])))]
    LOGGER.info("Total Folders Fetched: %s", len(bw_folders))
    # bw_exec.clear_cache()
    write_to_keepass()


if __name__ == "__main__":
    main()
