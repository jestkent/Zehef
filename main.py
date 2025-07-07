import sys
from lib.cli import parser
from lib.colors import *

async def main(email_arg=None):
    py_version = sys.version_info
    py_require = (3, 10)

    if py_version >= py_require:
        await parser(email_arg)

    else:
        exit(f"{RED}>{WHITE} Zehef doesn't work with Python version lower at 3.10.")