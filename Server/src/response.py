from Logger import log
from MessageEnum import *
from Data import ClientData
import struct


class Response:
    def __init__(self) -> None:
        self.version: int = None  # 1 byte
        self.code_type: int = None  # 2 bytes
        self.payload_size: int = None  # 4 bytes
        self.data = {}

    def init_header(self) -> bytes:
        fmt = "<BHI"
        log.debug(f"Response header: {struct.calcsize(fmt)} bytes")
        return struct.pack(fmt, self.version, self.code_type, self.payload_size)

    def pack(self):
        res_header = self.init_header()
        match self.code_type:
            case ResponseEnum.RES_ERROR:
                res_body = b""
            case ResponseEnum.REG_SUCCESS:
                res_body = struct.pack(f"!{ClientData.UUID_SIZE}s", self.data["UUID"])
            case ResponseEnum.SEND_USERS:
                res_body = struct.pack(f"!{ClientData.REQ_USER_SIZE * self.data['num_users']}s", self.data["users"])
            case ResponseEnum.PUB_KEY:
                res_body = struct.pack(f"!{ClientData.UUID_SIZE}s{ClientData.PUBLIC_KEY_SIZE}s", self.data["UUID"], self.data["PUBKEY"])
            case ResponseEnum.USER_MESSAGES:
                res_body = self.data["messages"]
            case ResponseEnum.MESSAGE_SENT:
                res_body = struct.pack(f"!{ClientData.UUID_SIZE}sI", self.data["msg_recipient"], self.data["msg_id"])
            case _:
                print("Response: Nothing")  # REMOVEME
                res_body = b""

        log.debug(f"Response: {ResponseEnum(self.code_type).name}: {len(res_body)} bytes, {res_body}")
        return res_header + res_body
