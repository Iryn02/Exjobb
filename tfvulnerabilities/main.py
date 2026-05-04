# -*- encoding: utf-8 -*-
# tfvulnerability v0.1.0
# Terraform vulnerability scanner and infrastructure environment setup
# Copyright 2026, Ida Rynger Johnny Norrman.
# See /LICENSE for licensing information.

"""
INSERT MODULE DESCRIPTION HERE.

:Copyright: 2026, Ida Rynger Johnny Norrman.
:License: GPLv3 (see /LICENSE).
"""

__all__ = ()

import sys
from tfvulnerabilities.cl_parser import parse_args
from Exjobb.tfvulnerabilities.main_script import *
from Exjobb.tfvulnerabilities.search_files import *



def main():
    """Main routine of tfvulnerability."""

    print("Hello World")
    args = parse_args(sys.argv[1:])
    cmd_params = vars(args)
    print(cmd_params)
