"""
This module defines Pydantic models for various Bitwarden entities.

Classes:
    BwItemLoginFido2Credentials: Represents Fido2 credentials associated with a Bitwarden login item.
    BwItemLoginUri: Represents a URI associated with a Bitwarden login item.
    BwItemLogin: Represents a Bitwarden login item.
    BwItemPasswordHistory: Represents the password history of a Bitwarden item.
    BwItemAttachment: Represents an attachment associated with a Bitwarden item.
    BwField: Represents a custom field associated with a Bitwarden item.
    BwItem: Represents a Bitwarden item.
    BwCollection: Represents a collection of Bitwarden items.
    BwOrganization: Represents a Bitwarden organization.
    BwFolder: Represents a folder in Bitwarden.

"""

from typing import Dict, List, Optional

from pydantic import BaseModel


class BwItemLoginFido2Credentials(BaseModel):
    """
    Bitwarden Fido2 Credentials Model
    """

    credentialId: str
    keyType: str
    keyAlgorithm: str
    keyCurve: str
    keyValue: str
    rpId: str
    userHandle: str
    userName: Optional[str] = None
    counter: str
    rpName: str
    userDisplayName: str
    discoverable: str
    creationDate: str


class BwItemLoginUri(BaseModel):
    """
    Bitwarden Login URI Model
    """

    match: Optional[int] = None
    uri: str


class BwItemLogin(BaseModel):
    """
    Bitwarden Login Model
    """

    username: Optional[str] = None
    password: Optional[str] = None
    totp: Optional[str] = None
    uris: List[BwItemLoginUri] = []
    passwordRevisionDate: Optional[str] = None
    fido2Credentials: Optional[List[BwItemLoginFido2Credentials]] = None


class BwItemPasswordHistory(BaseModel):
    """
    Bitwarden Password History Model
    """

    lastUsedDate: str
    password: str


class BwItemAttachment(BaseModel):
    """
    Bitwarden Attachment Model
    """

    id: str
    fileName: str
    size: str
    sizeName: str
    url: str
    local_file_path: str = ""


class BwField(BaseModel):
    """
    Bitwarden Field Model
    """

    name: str
    value: Optional[str] = None
    type: int
    linkedId: Optional[int] = None


class BwItem(BaseModel):
    """
    Bitwarden Item Model
    """

    passwordHistory: Optional[List[BwItemPasswordHistory]] = None
    revisionDate: str
    creationDate: str
    deletedDate: Optional[str] = None
    object: str
    id: str
    organizationId: Optional[str] = None
    folderId: Optional[str] = None
    type: int
    reprompt: int
    name: str
    notes: Optional[str] = None
    favorite: bool
    login: Optional[BwItemLogin] = None
    collectionIds: List[str] = []
    attachments: List[BwItemAttachment] = []
    fields: List[BwField] = []


class BwCollection(BaseModel):
    """
    Bitwarden Collection Model
    """

    object: str
    id: str
    organizationId: str
    name: str
    externalId: Optional[str] = None
    items: Dict[str, BwItem] = {}


class BwOrganization(BaseModel):
    """
    Bitwarden Organization Model
    """

    object: str
    id: str
    name: str
    status: int
    type: int
    enabled: bool
    collections: Dict[str, BwCollection] = {}


class BwFolder(BaseModel):
    """
    Bitwarden Folder Model
    """

    object: str
    id: Optional[str] = None
    name: str
    items: Dict[str, BwItem] = {}
