from Logger import log
from typing import Dict, AnyStr
from Data import ClientData
from MessageEnum import *
import struct

from Data import MessageData


class Request:
    def __init__(self, code_type: RequestEnum, client_id: bytes, data: bytes) -> None:
        self.code_type = code_type
        self.client_id = client_id
        self.unpack(data)

    @staticmethod
    def unpack_header(data):
        fmt_header = f"<{ClientData.UUID_SIZE}sBHI"
        return struct.unpack(fmt_header, data)

    def unpack_msg_header(self, data):
        fmt_header = f"<{ClientData.UUID_SIZE}sBI"
        self.data["msg_recipient"], self.data["msg_type"], self.data["msg_len"] = struct.unpack(fmt_header, data[: MessageData.MESSAGE_REQ_HEADER_SIZE])
        log.debug(f"MSG HEADER: \nToClient: {self.data['msg_recipient']}\nType: {self.data['msg_type']}\nLength: {self.data['msg_len']}")

    def unpack_register(self, data) -> Dict[AnyStr, AnyStr]:
        fmt = f"!{ClientData.USERNAME_SIZE}s{ClientData.PUBLIC_KEY_SIZE}s"
        username, public_key = struct.unpack(fmt, data)
        self.data["USERNAME"] = username.decode("utf-8")
        self.data["PUBKEY"] = public_key
        return self.data

    def unpack_req_public(self, data) -> Dict[AnyStr, AnyStr]:
        """
        This function is redundant as there is only one element in the body
        """
        fmt = f"!{ClientData.UUID_SIZE}s"
        uuid = struct.unpack(fmt, data)
        self.data["uuid"] = uuid[0]
        return self.data

    def unpack_send_msg(self, data) -> Dict:
        self.unpack_msg_header(data)

        fmt_body = f"!{self.data['msg_len']}s"
        if self.data["msg_len"] > 0:
            self.data["msg_body"] = struct.unpack(fmt_body, data[MessageData.MESSAGE_REQ_HEADER_SIZE :])[0]
        else:
            self.data["msg_body"] = b""
        log.debug(f"MSG BODY: {self.data['msg_body']}")
        return self.data

    def unpack(self, data: bytes) -> Dict:
        log.debug(f"Request: {self.code_type.name}")
        self.data = {}
        match self.code_type:
            case RequestEnum.REG_REQUEST:
                return self.unpack_register(data)
            case RequestEnum.LIST_USERS | RequestEnum.GET_MESSAGE:
                return self.data
            case RequestEnum.REQ_PUB:
                return self.unpack_req_public(data)
            case RequestEnum.SND_MESSAGE:
                return self.unpack_send_msg(data)
