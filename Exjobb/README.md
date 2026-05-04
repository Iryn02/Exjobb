# tfvulnerability.  Terraform vulnerability scanner and infrastructure environment setup

[![Build Status](https://travis-ci.com/iryn02/Exjobb.svg?branch=master)](https://travis-ci.com/iryn02/Exjobb)

Author: Ida Rynger Johnny Norrman <ida.rynger@gmail.com> <johnny.norrman@hotmail.com>

Copyright: © 2026, Ida Rynger, Johnny Norrman.

Date: 2026-01-19

Version: 0.1.0


## PURPOSE
This tool scans Terraform configurations for security vulnerabilities and automates the setup and deployment of infrastructure environments using Terraform and Kubernetes. It is a tool for analysing the possibilities for lateral movement between Kubernetes clusters based on known and published vulnerabilties on https://kubenomicon.com/

## PROJECT STRUKTURE

```
Exjobb/
├── README.md
├── LICENSE
├── Makefile
├── release
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── setup.cfg
├── .gitignore
├── docs/
│   ├── html/
│   │   └── index.html
│   ├── conf.py
│   └── index.rst
├── shell/
│   ├── cleanup.sh
│   └── join_workers.sh
└── tfvulnerabilities/
    ├── __init__.py
    ├── __main__.py
    ├── main_script.py
    ├── main.py
    ├── cl_parser.py
    ├── search_files.py
    ├── vulnFilesScript1.json
    └── terraform_repo/
        ├── base/
        │   ├── main.tf
        │   └── outputs.tf
        ├── host_path/
        │   ├── main.tf
        │   └── outputs.tf
        ├── managed_identity/
        │   ├── main.tf
        │   └── outputs.tf
        └── service_account/
            ├── main.tf
            └── outputs.tf
```

## INSTALLATION

We can install tfvulnerability simply by doing:
```sh
git clone https://github.com/iryn02/Exjobb
cd Exjobb
pip install -r requirements.txt
python setup.py install
```

## USAGE
Required packages listed in requirements.txt

Run the script from the `tfvulnerabilities` directory:

```sh
cd tfvulnerabilities
python main_script.py choice
```

### Choices

| Choice | Description                                |
|--------|--------------------------------------------|
| `1`    | Deploy base Kubernetes environment         |
| `2`    | Deploy writable hostpath environment       |
| `3`    | Deploy managed identity environment        |
| `4`    | Deploy service account environment         |
| `5`    | Scan Terraform files for misconfigurations |
| `6`    | Cleanup and tear down all VMs              |

### Examples

```sh
# Deploy the base environment
python main_script.py 1

# Scan Terraform files before deploying
python main_script.py 5

# Tear down all VMs when done
python main_script.py 6
```

**Note:** Deploying environments requires Terraform and Multipass to be installed.
Run option `5` before deploying to check for misconfigurations.


## NOTES

**OS Compatibility**
This project was developed and tested on Linux. Core functionality relies on
Bash scripts and Linux-specific commands. Running on macOS or Windows requires
adapting the shell scripts in `shell/` and any system calls in the source code.

**Permissions**
Some operations (installing dependencies, managing VMs) require sudo privileges.
You will be prompted when needed.

**Environment Warning**
This lab deploys intentionally vulnerable Kubernetes configurations for research
purposes. Do not deploy in a production environment or on exposed networks

## COPYRIGHT

Copyright 2026, Ida Rynger Johnny Norrman.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

