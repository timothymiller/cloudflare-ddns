#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

python3 -m venv venv
source ./venv/bin/activate

cd $DIR
set -o pipefail; pip install -r requirements.txt | { grep -v "already satisfied" || :; }

python3 cloudflare-ddns.py
