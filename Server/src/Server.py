from collections import defaultdict
from types import SimpleNamespace
from typing import Dict, List
import socket
import selectors

from Logger import log
from MessageEnum import *
from Data import MessageData, ClientData

from request import Request
from response import Response


class Server:
    VERSION = 1

    def __init__(self, port) -> None:
        self.port = port
        self.host = "127.0.0.1"
        self.users: Dict[ClientData] = {}
        # self.messages: List[MessageData] = []
        self.messages: Dict[bytes, List[MessageData]] = defaultdict(list)
        # self.message_id = 0

        self.response_handlers = {
            RequestEnum.REG_REQUEST: self.register_user,
            RequestEnum.LIST_USERS: self.list_users,
            RequestEnum.REQ_PUB: self.request_public,
            RequestEnum.SND_MESSAGE: self.send_message,
            RequestEnum.GET_MESSAGE: self.get_messages,
            RequestEnum.REQ_ERROR: self.res_error,
        }

    # def get_msg_id(self):
    #     self.message_id += 1
    #     return self.message_id

    def response_factory(self, req: Request, res: Response) -> None:
        res.version = self.VERSION
        self.response_handlers[req.code_type](req, res)

    def run(self):
        self.sel = selectors.DefaultSelector()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind((self.host, self.port))
                s.listen(10)
                log.info(f"Server listening on port {self.port}")
                s.setblocking(False)
                self.sel.register(s, selectors.EVENT_READ, data=None)

                while True:
                    events = self.sel.select(timeout=0)
                    for key, mask in events:
                        if key.data is None:
                            self.accept(key.fileobj)
                        else:
                            key.data["callback"](key, mask)
                            # self.handle_connection(key, mask)

            except KeyboardInterrupt:
                log.info("Closing server")
                exit(1)

    def accept(self, s):
        conn, addr = s.accept()
        log.info(f"[+] Connection established from {addr[0]}:{addr[1]}")
        conn.setblocking(False)
        data = {"callback": self.read, "addr": addr}
        self.sel.register(conn, selectors.EVENT_READ, data=data)

    def read(self, key, mask):
        conn = key.fileobj
        addr = key.data["addr"]

        print(f"ready to read!")
        header = conn.recv(HEADER_SIZE)
        if header:
            # Header
            log.debug("Received message ({} bytes): {}".format(len(header), header))
            client_id, _, code_type, length = Request.unpack_header(header)

            # Body
            data = conn.recv(length)
            log.debug("Received message ({} bytes): {}".format(len(data), data))
            key.data["req"] = Request(RequestEnum(code_type), client_id, data)
            data = key.data
            data["callback"] = self.write
            self.sel.modify(conn, selectors.EVENT_WRITE, data)

        else:
            log.info(f"[-] Connection terminated from {addr[0]}:{addr[1]}")
            self.sel.unregister(conn)
            conn.close()

    def write(self, key, mask):
        res = Response()
        self.response_factory(key.data["req"], res)

        key.fileobj.send(res.pack())
        self.sel.unregister(key.fileobj)

    def handle_connection(self, key: selectors.SelectorKey, mask):
        conn = key.fileobj
        addr = key.data["addr"]

        if mask & selectors.EVENT_READ:
            print(f"ready to read!")
            header = conn.recv(HEADER_SIZE)
            if header:
                # Header
                log.debug("Received message ({} bytes): {}".format(len(header), header))
                client_id, _, code_type, length = Request.unpack_header(header)

                # Body
                data = conn.recv(length)
                log.debug("Received message ({} bytes): {}".format(len(data), data))
                key.data["req"] = Request(RequestEnum(code_type), client_id, data)
                print(f"HEYYYY\n{key.data.req}")

            else:
                log.info(f"[-] Connection terminated from {addr[0]}:{addr[1]}")
                self.sel.unregister(conn)
                conn.close()

        if mask & selectors.EVENT_WRITE:
            print(f"ready to write!")
            with conn:
                # Response
                res = Response()
                print(f"HOYYYYY\n{key.data['req']}")
                self.response_factory(key.data["req"], res)

                conn.send(res.pack())

    # Request: REG_REQUEST -> Response: REG_SUCCESS/ERROR
    def register_user(self, req, res):
        username = req.data["USERNAME"]
        public_key = req.data["PUBKEY"]
        if username in self.users:
            log.info(f"'{username}' already exists")
            res.code_type = ResponseEnum.RES_ERROR
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
        if req.client_id in self.messages:
            log.debug(f"Number of messages: {len(self.messages[req.client_id])}")
            for message in self.messages[req.client_id]:
                res.payload_size += MessageData.MESSAGE_HEADER_SIZE + message.ContentSize
                res.data["messages"] += message.pack(req.client_id)
            log.debug(f"Sending messages: {res.payload_size} bytes")
        else:
            res.payload_size = 0
            res.data["messages"] = b""

    def send_message(self, req: Request, res):
        res.code_type = ResponseEnum.MESSAGE_SENT
        message = MessageData(req.data["msg_recipient"], req.client_id, req.data["msg_type"], req.data["msg_len"], req.data["msg_body"])
        self.messages[req.data["msg_recipient"]].append(message)

        res.data["msg_recipient"] = req.data["msg_recipient"]
        res.data["msg_id"] = message.ID
        res.payload_size = ClientData.UUID_SIZE + MessageData.CONTENT_SIZE

    def res_error(self, req, res):
        res.code_type = ResponseEnum.REQ_ERROR
        res.payload_size = 0
        res.data = None
