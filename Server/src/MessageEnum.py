from enum import IntEnum

HEADER_SIZE = 23
PAYLOAD_PACKET = 1024

# USERNAME_SIZE = 255
# UUID_SIZE = 16
# USER_SIZE = USERNAME_SIZE + UUID_SIZE
# PUBLIC_KEY_SIZE = 160


class RequestEnum(IntEnum):
    REG_REQUEST = 1100
    LIST_USERS = 1101
    REQ_PUB = 1102
    SND_MESSAGE = 1103
    GET_MESSAGE = 1104
    REQ_ERROR = 9000

    @classmethod
    def _missing_(cls, value):
        return RequestEnum.REQ_ERROR


class MessageType(IntEnum):
    REQ_SYM = 1
    SMD_SYM = 2
    SND_TXT = 3


class ResponseEnum(IntEnum):
    REG_SUCCESS = 2100
    SEND_USERS = 2101
    PUB_KEY = 2102
    MESSAGE_SENT = 2103
    USER_MESSAGES = 2104
    RES_ERROR = 9000
