from typing import Dict, List
import socket

from Logger import log
from MessageEnum import *
from Data import MessageData, ClientData

# from User import User
from request import Request
from response import Response


class Server:
    VERSION = 1

    def __init__(self, port) -> None:
        self.port = port
        self.host = "127.0.0.1"
        self.users: Dict[ClientData] = {}
        # self.messages: List[MessageData] = []
        self.messages: Dict[bytes, MessageData] = {}

        self.response_handlers = {
            RequestEnum.REG_REQUEST: self.register_user,
            RequestEnum.LIST_USERS: self.list_users,
            RequestEnum.REQ_PUB: self.request_public,
            RequestEnum.SND_MESSAGE: self.send_message,
            RequestEnum.GET_MESSAGE: self.get_messages,
        }

    def response_factory(self, req: Request, res: Response) -> None:
        res.version = self.VERSION
        self.response_handlers[req.code_type](req, res)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind((self.host, self.port))
                s.listen(10)
                log.info(f"Server listening on port {self.port}")
                while True:
                    # TODO: Configure selector and multiclient support
                    conn, addr = s.accept()
                    log.info(f"[+] Connection established from {addr[0]}:{addr[1]}")
                    with conn:
                        while True:
                            header = conn.recv(HEADER_SIZE)
                            if not header:
                                break

                            # Header
                            log.debug("Received message ({} bytes): {}".format(len(header), header))
                            client_id, _, code_type, length = Request.unpack_header(header)

                            # Body
                            data = conn.recv(length)
                            log.debug("Received message ({} bytes): {}".format(len(data), data))
                            req = Request(RequestEnum(code_type), client_id, data)

                            # Response
                            res = Response()
                            self.response_factory(req, res)

                            conn.send(res.pack())
                        log.info(f"[-] Connection terminated from {addr[0]}:{addr[1]}")
                        conn.close()

            except KeyboardInterrupt:
                log.info("Closing server")
                exit(1)

    # Request: REG_REQUEST -> Response: REG_SUCCESS/ERROR
    def register_user(self, req, res):
        username = req.data["USERNAME"]
        public_key = req.data["PUBKEY"]
        if username in self.users:
            log.info(f"'{username}' already exists")
            res.code_type = ResponseEnum.ERROR
            res.payload_size = 0
            res.data = b""
        else:
            user = ClientData(username, public_key)
            self.users[user.name] = user
            log.info(f"Server: new user '{username}'")
            res.code_type = ResponseEnum.REG_SUCCESS.value
            res.data["UUID"] = user.client_id
            log.debug(f"new uuid {user.client_id}")
            log.debug(f"new uuid {user.client_id.hex()}")
            res.payload_size = ClientData.UUID_SIZE

    def list_users(self, req, res):
        res.code_type = ResponseEnum.SEND_USERS.value
        num_users = len(self.users) - 1  # excluding the requester
        res.payload_size = 0 if ClientData.REQ_USER_SIZE * num_users < 0 else ClientData.REQ_USER_SIZE * num_users
        out = bytearray()
        for user in self.users.values():
            if user.client_id != req.client_id:
                out += user.client_id + user.name.encode()
        res.data["num_users"] = 0 if num_users < 0 else num_users
        res.data["users"] = out

    def request_public(self, req, res: Response):
        res.code_type = ResponseEnum.PUB_KEY.value
        res.payload_size = ClientData.REQ_PUBKEY_SIZE
        for user in self.users.values():
            if user.client_id == req.data["uuid"]:
                res.data["UUID"] = user.client_id
                res.data["PUBKEY"] = user.public_key
                break

    def get_messages(self, req: Request, res):
        res.code_type = ResponseEnum.USER_MESSAGES
        res.payload_size = 0
        res.data["messages"] = bytearray()
        for message in self.messages[req.client_id]:
            res.payload_size += MessageData.MESSAGE_HEADER_SIZE + message.CONTENT_SIZE
            res.data["messages"] += message.pack(req.client_id)

    def send_message(self, req, res):
        res.code_type = ResponseEnum.MESSAGE_SENT
