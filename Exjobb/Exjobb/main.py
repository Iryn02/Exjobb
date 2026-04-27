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
from tfvulnerability.cl_parser import parse_args



def main():
    """Main routine of tfvulnerability."""

    print("Hello World")
    args = parse_args(sys.argv[1:])
    cmd_params = vars(args)
    print(cmd_params)
