#!/usr/bin/env python3
# -*- Mode: Python; tab-width: 4 -*-
#
# WireShark Paste Utility to copy whole packet bytes as Hex Stream
#
# Copyright (C) 2005-2007 Gianluigi Tiesi <sherpya@netfarm.it>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
# ======================================================================
from sys import stdin, argv, exit as sys_exit

if __name__ == '__main__':

    if len(argv) != 2:
        print(f'Usage: {argv[0]} destfile')
        sys_exit(1)

    data = stdin.read().strip()[0x2a*2:]

    if len(data) % 2:
        print('Bad input data')
        sys_exit(1)

    fd = open(argv[1], 'wb')
    fd.write(bytes.fromhex(data))
    fd.close()
