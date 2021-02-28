import sys

from pathlib import Path
from uuid import uuid4

TOKEN_PATH = "nextcloud-proxy.tokens"
NUM_TOKENS = 10000

p = Path(TOKEN_PATH)

if p.exists():
    print(f"'{TOKEN_PATH}' already exists, (re)move it first!")
    sys.exit(1)

tokens = []
for _ in range(NUM_TOKENS):
    tokens.append(str(uuid4()).upper() + "\n")

with p.open("w") as fd:
    fd.writelines(tokens)



