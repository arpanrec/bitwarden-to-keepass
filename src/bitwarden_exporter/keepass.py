"""
Writes the given data to a file at the specified path.
"""

import logging
import urllib.parse
from types import TracebackType
from typing import Dict, List, Optional, Type, Union

from pykeepass import PyKeePass, create_database  # type: ignore
from pykeepass.entry import Entry  # type: ignore
from pykeepass.group import Group  # type: ignore

from . import BitwardenException
from .bw_models import BwItem, BwOrganization

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


class KeePassStorage:
    """
    Class to interact with Keepass
    """

    __py_kee_pass: PyKeePass

    def __init__(self, kdbx_file: str, kdbx_password: str) -> None:
        self.__kdbx_file = kdbx_file
        self.__kdbx_password = kdbx_password

    def __enter__(self) -> "KeePassStorage":
        LOGGER.info("Creating Keepass Database: %s, Password: password", self.__kdbx_file)
        self.__py_kee_pass = create_database(self.__kdbx_file, password=self.__kdbx_password)
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        try:
            self.__py_kee_pass.save()
            LOGGER.info("Keepass Database Saved")
        except Exception as e:  # pylint: disable=broad-except
            LOGGER.error("Error in saving Keepass Database %s", e)
            raise BitwardenException("Error in saving Keepass Database") from e

        if exc_type is not None:
            LOGGER.error("Error in processing %s", exc_value)
            raise BitwardenException("Error in processing") from exc_value

        return True

    def __add_group_recursive(self, parent_group: Group, group_path: str) -> Group:
        """
        Recursively add group to Keepass
        """

        if "/" in group_path:
            group_name = group_path.split("/")[0]
            existing_subgroups: List[Group] = parent_group.subgroups
            for subgroup in existing_subgroups:
                if subgroup.name == group_name:
                    return self.__add_group_recursive(subgroup, "/".join(group_path.split("/")[1:]))
            new_group = self.__py_kee_pass.add_group(parent_group, group_name=group_name)
            return self.__add_group_recursive(new_group, "/".join(group_path.split("/")[1:]))
        return self.__py_kee_pass.add_group(parent_group, group_name=group_path)

    def __add_entry(self, group: Group, bw_item: BwItem) -> Entry:
        """
        Add an entry to Keepass
        """
        entry: Entry = self.__py_kee_pass.add_entry(
            destination_group=group,
            title=bw_item.name,
            username="" if (not bw_item.login) or (not bw_item.login.username) else bw_item.login.username,
            password="" if (not bw_item.login) or (not bw_item.login.password) else bw_item.login.password,
        )
        LOGGER.info("Adding Entry %s", bw_item.name)
        self.__add_fields(entry, bw_item)
        self.__add_attachment(entry, bw_item)
        self.__add_otp(entry, bw_item)

        if bw_item.notes:
            entry.notes = bw_item.notes

        return entry

    @staticmethod
    def __add_otp(entry: Entry, bw_item: BwItem) -> None:
        """
        Add OTP to Keepass
        """
        if (not bw_item.login) or (not bw_item.login.totp):
            return None

        LOGGER.info("Adding OTP for %s", bw_item.name)
        if not bw_item.login.totp.startswith("otpauth://"):
            url_safe_totp = bw_item.login.totp.replace(" ", "").lower()
            url_safe_name = urllib.parse.quote_plus(bw_item.name)
            bw_item.login.totp = (
                f"otpauth://totp/{url_safe_name}?secret={url_safe_totp}"
                f"&issuer={url_safe_name}&algorithm=SHA1&digits=6&period=30"
            )
            bw_item.login.totp = bw_item.login.totp
        entry.otp = bw_item.login.totp
        return None

    @staticmethod
    def __add_fields(entry: Entry, item: BwItem) -> None:
        """
        Add fields to Keepass
        """
        LOGGER.info("%s:: Adding Custom Fields to custom_properties", item.name)
        all_field_names = [] + list(entry.custom_properties.keys())
        for field in item.fields:
            if field.name in all_field_names:
                LOGGER.warning("%s:: Field with name %s already exists, Adding -1", item.name, field.name)
                field.name = f"{field.name}-1"
            if field.name == "otp":
                LOGGER.warning("%s:: Field with name otp is reserved in keepass, Changing to otp-1", item.name)
                field.name = "otp-1"
            all_field_names.append(field.name)
            entry.set_custom_property(field.name, field.value, protect=False)

    def __add_attachment(self, entry: Entry, item: BwItem) -> None:
        """
        Add an attachment to Keepass
        """
        LOGGER.info("%s:: Adding Attachments", item.name)
        all_names = [] + [attachment.fileName for attachment in entry.attachments]
        for attachment in item.attachments:
            LOGGER.info("%s:: Adding Attachment to keepass %s", item.name, attachment.fileName)
            if attachment.fileName in all_names:
                LOGGER.warning("%s:: Attachment with name %s already exists, Adding -1", item.name, attachment.fileName)
                attachment.fileName = f"{attachment.fileName}-1"
            all_names.append(attachment.fileName)
            with open(attachment.local_file_path, "rb") as file_attach:
                binary_id = self.__py_kee_pass.add_binary(data=file_attach.read(), protected=False, compressed=False)
                entry.add_attachment(binary_id, attachment.fileName)

    def process_organizations(self, bw_organizations: Dict[str, BwOrganization]) -> None:
        """
        Function to write to Keepass
        """

        for organization in bw_organizations.values():
            LOGGER.info("Processing Organization %s", organization.name)
            organization_group: Group = self.__py_kee_pass.add_group(
                destination_group=self.__py_kee_pass.root_group, group_name=organization.name
            )
            collections = organization.collections
            organization.collections = {}
            organization_group.notes = organization.model_dump_json()
            for collection in collections.values():
                LOGGER.info("%s:: Processing Collection %s", organization.name, collection.name)
                collection_group = self.__add_group_recursive(organization_group, collection.name)
                items = collection.items
                collection.items = {}
                collection_group.notes = collection.model_dump_json()
                for item in items.values():
                    LOGGER.info("%s::%s:: Processing Item %s", organization.name, collection.name, item.name)
                    try:
                        self.__add_entry(collection_group, item)
                    except Exception as e:  # pylint: disable=broad-except
                        LOGGER.error("Error adding entry %s", e)
                        raise BitwardenException("Error adding entry") from e
