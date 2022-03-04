import os
import sys
from Logger import *
from Server import Server


def run():
    server_info = "info.myport"
    cwd = os.path.dirname(__file__)
    log.debug(f"Loading server infomation from {cwd}")
    os.chdir(cwd)
    with open(server_info, "r") as f:
        port_num = int(f.read(1024))
        log.info(f"Port number: {port_num}")
        Server(port_num).run()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].upper() == "DEBUG":
        log.setLevel(logging.DEBUG)
    run()
