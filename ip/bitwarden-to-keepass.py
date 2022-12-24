import json
import os

from pykeepass import PyKeePass, create_database

create_database("dump/Passwords.kdbx", "1234")

with open(r"dump/bitwarden_export.json", 'r') as bw_exported_json_file:
    bw_exported_json = json.load(bw_exported_json_file)
keepass_database = PyKeePass("dump/Passwords.kdbx", password="1234")
bw_folders_dict: dict = {}

for bw_folder in bw_exported_json["folders"]:
    if bw_folder is not None:
        bw_folders_dict[bw_folder["id"]] = bw_folder["name"]
        group_broken_list = bw_folder["name"].split("/")
        parent_group = keepass_database.root_group
        for group_name in group_broken_list:
            find_groups_path = "/".join(parent_group.path) + '/' + group_name
            find_groups_result = keepass_database.find_groups(
                path=find_groups_path[1:] if find_groups_path.startswith('/') else find_groups_path,
                first=True
            )
            if find_groups_result is None:
                parent_group = keepass_database.add_group(
                    parent_group, group_name)
            else:
                parent_group = find_groups_result

for item in bw_exported_json["items"]:
    if item["folderId"] is not None:
        folder_path = bw_folders_dict[item["folderId"]]
        for group_in_db in keepass_database.groups:
            if "/".join(group_in_db.path) == folder_path:
                destination_group = group_in_db
                break
    else:
        destination_group = keepass_database.root_group

    keepass_entry = keepass_database.add_entry(
        destination_group, item["name"],
        item["login"]["username"] if (item["login"]["username"] is not None) else "",
        item["login"]["password"] if (item["login"]["password"] is not None) else "",
        notes=item["notes"] if (item["notes"] is not None) else ""
    )

    if item["login"].get("uris") is not None and item["login"].get("uris")[0]["uri"] is not None:
        keepass_entry.url = item["login"]["uris"][0]["uri"]
    keepass_entry.autotype_enabled = None
    if item.get("fields"):
        for field in item.get("fields"):
            keepass_entry.set_custom_property(field["name"], field["value"])

    if item["login"]["totp"] is not None:
        keepass_entry.set_custom_property("otp", item["login"]["totp"])

keepass_database.save()
