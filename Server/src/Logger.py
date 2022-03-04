from fileinput import filename
import logging

logging.basicConfig(
    level=logging.INFO,
    encoding="utf-8",
    datefmt="%m/%d/%Y %H:%M:%S",
    format="%(asctime)s::%(levelname)s %(message)s",
)

log = logging.getLogger("Server")
log.info("Initializing logger")
