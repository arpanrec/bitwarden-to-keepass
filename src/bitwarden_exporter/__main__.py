#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os.path
import subprocess
import time
from typing import Dict, List, Optional
from .models import BwItem
from .write_to_file import EncryptAndWriteToFile, WriteToFile

LOGGER = logging.getLogger(__name__)


def bw_exec(cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None) -> str:
    cmd = ["bw"] + cmd + ["--raw"]

    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)
    print(f"Executing CLI :: {' '.join(cmd)}")
    command_out = subprocess.run(cmd, capture_output=True, check=False, encoding=ret_encoding, env=cli_env_vars)
    if len(command_out.stderr) > 0:
        raise Exception(f"Error in executing command {command_out.stderr}")
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
    parser.add_argument("-g", "--gpg-fpr", help="gpg-key-id for file encryption")
    args, unknown = parser.parse_known_args()

    if bw_current_status["status"] != "unlocked":
        raise Exception("Unable to unlock the vault")

    if args.gpg_fpr is None:
        file_writer = WriteToFile()
    else:
        file_writer = EncryptAndWriteToFile(args.gpg_fpr)

    # Syn latest version
    bw_sync_status = bw_exec(["sync"])

    # Fetch Organization Details
    bw_organizations = json.loads((bw_exec(["list", "organizations"])))
    bw_items = json.loads((bw_exec(["list", "items"])))
    bw_folders = json.loads((bw_exec(["list", "folders"])))
    bw_collections = json.loads((bw_exec(["list", "collections"])))

    items_lists_based_on_organization: dict = {}
    attachments_list: list = []
    for bw_organization in bw_organizations:
        items_lists_based_on_organization[bw_organization["id"]] = {"collections": [], "folders": [], "items": []}
    items_lists_based_on_organization[bw_current_status["userId"]] = {"collections": [], "folders": [], "items": []}

    while len(bw_items) > 0:
        bw_item = bw_items.pop()
        logging.debug("bw item: %s" % bw_item)
        bw_item_model: BwItem = BwItem(**bw_item)
        print(f"Downloading Item \n {bw_item_model}")
        if bw_item["organizationId"] is not None:
            items_lists_based_on_organization[bw_item["organizationId"]]["items"].append(bw_item)
            org_or_user_id = bw_item["organizationId"]
        else:
            items_lists_based_on_organization[bw_current_status["userId"]]["items"].append(bw_item)
            org_or_user_id = bw_current_status["userId"]

        if "attachments" not in bw_item:
            continue
        for attachment in bw_item["attachments"]:
            print(f"Downloading Attachment \n {attachment}")
            path = os.path.join(
                os.path.abspath(args.directory), org_or_user_id, "attachments", bw_item["id"], attachment["id"]
            )
            if not os.path.exists(path):
                os.makedirs(path)

            attachment_cmd_out = bw_exec(
                ["get", "attachment", "--itemid", bw_item["id"], attachment["id"]], ret_encoding=""
            )

            file_writer.write(attachment_cmd_out, os.path.join(path, attachment["fileName"]))

    while len(bw_folders) > 0:
        bw_folder = bw_folders.pop()
        items_lists_based_on_organization[bw_current_status["userId"]]["folders"].append(bw_folder)

    while len(bw_collections) > 0:
        bw_collection = bw_collections.pop()
        items_lists_based_on_organization[bw_collection["organizationId"]]["collections"].append(bw_collection)

    for export_dict, org_details in items_lists_based_on_organization.items():
        print(export_dict)
        path = os.path.join(os.path.abspath(args.directory), export_dict)
        if not os.path.exists(path):
            os.makedirs(path)
        file_writer.write(
            json.dumps(items_lists_based_on_organization[export_dict], indent=4), os.path.join(path, "export.json")
        )


if __name__ == "__main__":
    main()
