import json
import os

from pykeepass import PyKeePass
from striprtf.striprtf import rtf_to_text

keepass_database = PyKeePass(filename=r'dump/Passwords.kdbx',
                             password=os.getenv("KEEPASS_DATABASE_PASSWORD"))

bw_items: list = []
bw_folders: list = []

for entry in keepass_database.entries:
    group_already_added = False
    totp = None
    bw_fields: list = []
    # Get the group name
    # and set the value in group_str
    if entry.group.is_root_group:
        group_str = None
    else:
        group_str = "/".join(entry.group.path)

    for existing_bw_folder in bw_folders:
        if group_str is not None and existing_bw_folder['name'] == group_str:
            group_already_added = True
            break

    if group_str is not None and not group_already_added:
        bw_folders.append({'name': group_str, 'id': group_str})

    for existing_item in bw_items:
        if existing_item['name'] == entry.title:
            raise Exception(f'duplicate :: {entry.title} ')

    for custom_property in entry.custom_properties:
        if custom_property == 'otp':
            totp = entry.get_custom_property(custom_property)
        else:
            bw_fields.append(
                {
                    "type": 1,
                    'name': custom_property,
                    'value': entry.get_custom_property(custom_property)
                }
            )

    for attachment in entry.attachments:
        if attachment.filename in entry.custom_properties:
            raise Exception(
                'Field issue :: Attachment filename is already a attribute')

        if attachment.filename.endswith('rtf'):
            rtf = attachment.data.decode('utf-8')
            text = rtf_to_text(rtf)
        else:
            text = attachment.data.decode('utf-8')

        bw_fields.append({'name': attachment.filename, 'value': text})

    bw_item: dict = \
        {
            'type': 1,
            'favorite': False,
            'name': entry.title,
            'folderId': group_str,
            'fields': bw_fields,
            'login': {'uris': [{'uri': entry.url}],
                      'username': entry.username,
                      'password': entry.password,
                      'totp': totp
                      },
            'notes': entry.notes
        }
    bw_items.append(bw_item)

    bw_final_item: dict = {'encrypted': False,
                           'folders': bw_folders, 'items': bw_items}
    with open(r"dump/bitwarden_export.json", 'w') as json_file:
        json.dump(bw_final_item, json_file)
