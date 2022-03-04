from dataclasses import dataclass
import struct
import uuid
from datetime import datetime
from typing import ByteString
from dataclasses import dataclass
from MessageEnum import MessageType


@dataclass(init=False)
class ClientData:
    USERNAME_SIZE = 255
    UUID_SIZE = 16
    PUBLIC_KEY_SIZE = 160
    REQ_USER_SIZE = USERNAME_SIZE + UUID_SIZE
    REQ_PUBKEY_SIZE = UUID_SIZE + PUBLIC_KEY_SIZE

    name: str  # 255 Bytes
    # TODO: change to PKI class or something
    public_key: str  # 160 bytes
    client_id: uuid.UUID.bytes_le  # 16 bytes
    LastSeen: datetime  # sizecalc(datetime) ?

    def __init__(self, name: str, public_key: str) -> None:
        self.name = name
        self.public_key = public_key
        self.client_id = self.generate_uuid()

    def generate_uuid(self):
        return uuid.uuid4().bytes_le


@dataclass(init=True)
class MessageData:
    ID_SIZE = 4
    TYPE_SIZE = 1
    CONTENT_SIZE = 4
    MESSAGE_HEADER_SIZE = ClientData.UUID_SIZE + TYPE_SIZE + CONTENT_SIZE

    ID: int  # 4 bytes
    ToClient: int  # 16 bytes
    FromClient: int  # 16 bytes
    Type: MessageType  # 1 byte
    ContentSize: int  # 4 bytes
    Content: ByteString  # Blob?

    def pack(self, client_id):
        return struct.pack(f"!{ClientData.UUID_SIZE}sBI{self.ContentSize}s", client_id, self.Type, self.ContentSize, self.Content)