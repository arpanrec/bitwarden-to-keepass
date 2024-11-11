from typing import List, Optional

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
    uris: Optional[List[BwItemLoginUri]] = None
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


class BwField(BaseModel):
    """
    Bitwarden Field Model
    """

    name: str
    value: str
    type: int
    linkedId: Optional[str] = None


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
    collectionIds: Optional[List[str]] = None
    attachments: Optional[List[BwItemAttachment]] = None
    fields: Optional[List[BwField]] = None


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


class BwCollection(BaseModel):
    """
    Bitwarden Collection Model
    """

    object: str
    id: str
    organizationId: str
    name: str
    externalId: Optional[str] = None


class BwFolder(BaseModel):
    """
    Bitwarden Folder Model
    """

    object: str
    id: Optional[str] = None
    name: str
