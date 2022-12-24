#!/bin/python3
import os
import subprocess
import json
import shutil
import configargparse
from write_to_file import WriteToFile, EncryptAndWriteToFile

COMMON_CLI_PARAMS: list = ['--raw']


def bw_exec(cmd: list, ret_encoding='UTF-8', env_vars=None):
    cmd.extend(COMMON_CLI_PARAMS)
    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)
    print('Executing CLI :: %s' % ' '.join(cmd))
    command_out = subprocess.run(cmd, capture_output=True, encoding=ret_encoding, env=cli_env_vars)

    if len(command_out.stdout) > 0:
        return command_out.stdout
    elif len(command_out.stderr) > 0:
        return command_out.stderr


def export_and_download(json_export_dir, export_cmd, writer, all_items):
    if os.path.exists(json_export_dir):
        shutil.rmtree(json_export_dir)
    os.makedirs(json_export_dir)
    export_json = json.loads((bw_exec(export_cmd)))

    print('Received Raw Exported Json')

    json_export_path = os.path.join(json_export_dir, 'export.json')

    writer.write(json.dumps(export_json, indent=4), json_export_path)

    print(f'Written Exported data to {json_export_path}')

    for item in export_json['items']:
        print(f'Getting details for item : {item["id"]}')
        item_details: dict = {}
        for item_in_list in all_items:
            if item_in_list['id'] == item['id']:
                item_details = item_in_list
                break

        download_attachments_from_item_list(item_details, json_export_dir, writer)


def download_attachments_from_item_list(item_details_attach, json_export_dir, writer):
    # item_details = json.loads((bw_exec(['bw', 'get', 'item', item['id']])))
    if 'attachments' in item_details_attach:
        print('Attachment//s found in item')
        for attachment in item_details_attach['attachments']:

            print(f"Downloading Attachment \n {attachment}")

            attachment_export_dir = os.path.join(json_export_dir, 'attachments', item_details_attach['id'], attachment['id'])

            if not os.path.exists(attachment_export_dir):
                os.makedirs(attachment_export_dir)

            attachment_cmd_out = bw_exec(['bw', 'get', 'attachment', '--itemid', item_details_attach['id'], attachment['id']], ret_encoding=None)

            writer.write(attachment_cmd_out, os.path.join(attachment_export_dir, attachment['fileName']))


if __name__ == '__main__':

    bw_current_status = json.loads(bw_exec(["bw", "status"]))

    parser = configargparse.ArgParser()
    parser.add_argument("-d", '--directory', help="Bitwarden Dump Location", default='dump')
    parser.add_argument("-f", '--force-logout', help="logout of any existing session", default=False, action="store_true")
    parser.add_argument("-g", '--gpg-fpr', help="gpg-key-id for file encryption")
    parser.add_argument('--master-password', help="Bitwarden master password", required=True, env_var='BW_MASTERPASSWORD')
    parser.add_argument("-s", '--official-export', help="Official Export Methods, this requires master password to be provided in CLI", default=False, action="store_true")
    args, unknown = parser.parse_known_args()

    if args.force_logout:
        print(bw_exec(["bw", "logout"]))
        bw_current_status = json.loads(bw_exec(["bw", "status"]))

    # Login using api key
    if bw_current_status['status'] == 'unauthenticated':
        parser.add_argument('--client-id', help="Bitwarden API Client ID, or set BW_CLIENTID as enviourment variable", required=True, env_var='BW_CLIENTID')
        parser.add_argument('--client-secret', help="Bitwarden API Client Secret, or set BW_CLIENTSECRET as enviourment variable",
                            required=True, env_var='BW_CLIENTSECRET')
        args, unknown = parser.parse_known_args()
        print(bw_exec(["bw", "login", '--apikey', args.master_password], env_vars=dict(BW_CLIENTID=args.client_id, BW_CLIENTSECRET=args.client_secret)))
        bw_current_status = json.loads(bw_exec(["bw", "status"]))

    if bw_current_status['status'] == 'locked':
        session_id = bw_exec(["bw", "unlock", args.master_password])
        COMMON_CLI_PARAMS.append('--session')
        COMMON_CLI_PARAMS.append(session_id)
        bw_current_status = json.loads(bw_exec(["bw", "status"]))

    if bw_current_status['status'] != 'unlocked':
        raise Exception('Unable to unlock the vault')

    if args.gpg_fpr is None:
        file_writer = WriteToFile()
    else:
        file_writer = EncryptAndWriteToFile(args.gpg_fpr)

    # Syn latest version
    bw_sync_status = bw_exec(["bw", "sync"])
    # if bw_sync_status != 'Syncing complete.':
    #    raise Exception('Failed to sync vault :: ' + bw_sync_status)

    # Fetch Organization Details
    organizations = json.loads((bw_exec(['bw', 'list', 'organizations'])))

    all_items_array = json.loads((bw_exec(['bw', 'list', 'items'])))

    for organization in organizations:
        if organization['type'] < 2:
            org_id = organization['id']
            org_export_path = os.path.join(os.path.abspath(args.directory), str(org_id))
            org_export_cmd = ['bw', 'export', '--organizationid', str(org_id), '--format', 'json', args.master_password]
            export_and_download(org_export_path, org_export_cmd, file_writer, all_items_array)

    # Set the user export path
    user_export_path = os.path.join(os.path.abspath(args.directory), bw_current_status['userId'])

    # Set the user export cmd
    user_export_cmd = ['bw', 'export', '--format', 'json', args.master_password]

    export_and_download(user_export_path, user_export_cmd, file_writer, all_items_array)
