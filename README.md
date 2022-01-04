# aws_inventory script

Needed something quick and painless to create a spreadsheet with list of types of AWS resources with relevent information to do some inventory work. This will get a list of profiles that are set up and allow the ones to be scanned to be selected.

Tested and used with Python 3.

## Basic Usage

1. Set up python virtual environment (Recommended)
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install required python libraries
   ```bash
   pip install -r requirements.txt
   ```
3. Run `python inventory.py` and answer necessary questions.