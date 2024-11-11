from typing import Optional, List

from pydantic import BaseModel, PositiveInt


class BwItemLoginFido2Credentials(BaseModel):
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
    match: Optional[int] = None
    uri: str


class BwItemLogin(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    totp: Optional[str] = None
    uris: Optional[List[BwItemLoginUri]] = None
    passwordRevisionDate: Optional[str] = None
    fido2Credentials: Optional[List[BwItemLoginFido2Credentials]] = None


class BwItemPasswordHistory(BaseModel):
    lastUsedDate: str
    password: str


class BwItemAttachment(BaseModel):
    id: str
    fileName: str
    size: str
    sizeName: str
    url: str


class BwItem(BaseModel):
    passwordHistory: Optional[List[BwItemPasswordHistory]] = None
    revisionDate: str
    creationDate: str
    deletedDate: Optional[str] = None
    object: str
    id: str
    organizationId: Optional[str] = None
    folderId: Optional[str] = None
    type: PositiveInt
    reprompt: int
    name: str
    notes: Optional[str] = None
    favorite: bool
    login: Optional[BwItemLogin] = None
    collectionIds: Optional[list] = None
    attachments: Optional[List[BwItemAttachment]] = None
