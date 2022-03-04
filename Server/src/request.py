from Logger import log
from typing import Dict, AnyStr
from Data import ClientData
from MessageEnum import *
import struct


class Request:
    def __init__(self, code_type: RequestEnum, client_id: bytes, data: bytes) -> None:
        self.code_type = code_type
        self.client_id = client_id
        self.unpack(data)

    @staticmethod
    def unpack_header(data):
        fmt_header = "<16sBHI"
        return struct.unpack(fmt_header, data)

    def unpack_register(self, data) -> Dict[AnyStr, AnyStr]:
        fmt = f">{ClientData.USERNAME_SIZE}s{ClientData.PUBLIC_KEY_SIZE}s"
        username, public_key = struct.unpack(fmt, data)
        self.data["USERNAME"] = username.decode("utf-8")
        self.data["PUBKEY"] = public_key
        return self.data

    def unpack_req_public(self, data) -> Dict[AnyStr, AnyStr]:
        fmt = f">{ClientData.UUID_SIZE}s"
        uuid = struct.pack(fmt, data)
        self.data["uuid"] = uuid
        return self.data

    def unpack(self, data) -> Dict:
        log.debug(f"Request: {self.code_type.name}")
        self.data = {}
        match self.code_type:
            case RequestEnum.REG_REQUEST:
                return self.unpack_register(data)
            case RequestEnum.LIST_USERS | RequestEnum.GET_MESSAGE:
                return self.data
            case RequestEnum.REQ_PUB:
                return self.unpack_req_public(data)
