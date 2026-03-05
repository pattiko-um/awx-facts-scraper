## awx-facts-scraper

A simple Python application that queries the AWX API for information about hosts, primarily related to security compliance.

## Installation and Execution

- Download the repository using `git clone` or download the ZIP directly from GitHub
- Populate a local .env file with the following variables
  - export AWX_USER={awx username}
  - export AWX_PASS={awx password}
- Open the directory in Terminal and run `source .env` to load the variables in your environment. (This can also be done directly in your terminal shell.)
- Run `python main.py`

The script will start, and you will see it iterate through the hosts in the collections that your AWX account has access to. 

When it's finished, a file called `hosts.csv` will appear in the app directory.
