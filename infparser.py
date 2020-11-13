#!/usr/bin/env python3
# -*- Mode: Python; tab-width: 4 -*-
#
# Inf Driver parser
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

from codecs import utf_16_le_decode, BOM_LE, BOM_BE
from sys import argv, exit as sys_exit
from os.path import isfile
from glob import glob
from pickle import dump
from traceback import format_exc

__version__ = '1.0'

class_guids = ['{4d36e972-e325-11ce-bfc1-08002be10318}']
classes = ['net']

exclude = ['layout.inf', 'drvindex.inf', 'netclass.inf']

debug = 0
dumpdev = 0

bustype = { 'USB'   :  1,
            'PCI'   :  5,
            'PCMCIA':  8,
            'ISAPNP': 14
            }

def csv2list(value):
    values = value.strip().split(',')
    for i in range(len(values)):
        values[i] = values[i].strip()
    return values

def str_lookup(dc, c_key):
    for key, value in dc.items():
        if key.lower() == c_key.lower():
            if value:
                return value.pop()
    return 'NoDesc'

def item_lookup(dc, c_key):
    for key, value in dc.items():
        if key.lower() == c_key.lower():
            return value
    return None

def fuzzy_lookup(strlist, pattern, ends=None):
    for s in strlist:
        if ends is not None and not s.endswith('services'): continue
        if s.startswith(pattern): return s
    return None


def unquote(text):
    return ''.join(text.split('"'))

def skip_inf(line):
    ## Check if driver is requested
    if line.find('=') == -1: return False
    key, value = line.split('=', 1)
    key = key.strip().lower()
    value = value.strip().lower()
    if key == 'class' and value not in classes: return True
    if key == 'classguid' and value not in class_guids: return True
    return False

def parse_line(sections, secname, lineno, line):
    equal = line.find('=')
    comma = line.find(',')
    if equal + comma != -2:
        if equal == -1:
            equal = comma+1
        if comma == -1:
            comma = equal+1

    if debug > 2: print(f'[{lineno}] [{secname}] equal = {equal} - comma = {comma}')

    if len(line) + equal + comma == -1:
        if debug: print(f'[{lineno}] [{secname}] Invalid line')
        return True

    ### Values
    if equal < comma:
        if not isinstance(sections[secname], dict):
            sections[secname] = {}
        section = sections[secname]
        key, value = line.split('=', 1)
        key = key.strip()

        ### SkipList
        if key == '0':return True

        if key in section:
            values = csv2list(value)
            ### SkipList
            if (len(values) < 2) or (value.find('VEN_') == -1) or (value.find('DEV_') == -1):
                return True
            oldkey = key
            key = key + '_dev_' + values[1]

            if debug > 1:
                print(f'[{lineno}] [{secname}] Duplicate key {oldkey} will be renamed to {key}')

        if secname == 'manufacturer':
            mlist = value.strip().split(',')
            mf = mlist[0].strip().lower()
            if len(mlist) > 1:
                ml = []
                for m in mlist[1:]:
                    ml.append('.'.join([mf, m.strip().lower()]))
                mlist = [mf] + ml
            else:
                mlist = [mf]

            if debug > 0: print('Preprocessing Manifacturers:', ', '.join(mlist))
            section[key] = mlist
            if debug > 0: print(f'Manifacturer {key}={section[key]}')
            return True

        section[key] = csv2list(value)
        if debug > 1: print(f'[K] [{lineno}] [{secname}] {key}={section[key]}')
        return True

    values = csv2list(line)
    if debug > 1: print(f'[V] [{lineno}] [{secname}] Values = {",".join(values)}')
    sections[secname] = values
    return True

def parse_inf(filename):
    lineno = 0
    name = ''
    sections = {}
    section = None
    data = open(filename, 'rb').read()

    ## Cheap Unicode to ascii
    if data[:2] == BOM_LE or data[:2] == BOM_BE:
        data = utf_16_le_decode(data)[0]
        data = data.encode('ascii', 'ignore')
    data = data.decode()

    ## De-inf fixer ;)
    data = 'Copy'.join(data.split(';Cpy'))
    data = '\n'.join(data.split('\r\n'))
    data = ''.join(data.split('\\\n'))

    for line in data.split('\n'):
        lineno = lineno + 1
        line = line.strip()
        line = line.split(';', 1)[0]
        line = line.strip()

        if len(line) < 1: continue # empty lines

        if line[0] == ';': continue # comment

        ## We only need network drivers
        if name == 'version' and skip_inf(line):
            if debug > 0: print(f'Skipped {filename} not a network inf')
            return None

        ## Section start
        if line.startswith('[') and line.endswith(']'):
            name = line[1:-1].lower()
            sections[name] = {}
            section = sections[name]
        else:
            if section is None: continue
            if not parse_line(sections, name, lineno, line):
                break
    return sections

def scan_inf(filename):
    if debug > 0: print('Parsing ', filename)
    inf = parse_inf(filename)
    if inf is None: return {}

    devices = {}
    if inf and 'manufacturer' in inf:
        devlist = sum(inf['manufacturer'].values(), [])
        if debug > 0: print('Devlist:', ', '.join(devlist))
        for devmap in devlist:
            devmap_k = unquote(devmap.lower())
            if devmap_k not in inf:
                if debug > 0: print(f'Warning: missing [{devmap}] driver section in {filename}, ignored')
                continue
            devmap = devmap_k
            for dev in inf[devmap]:
                if dev.find('%') == -1: continue # bad infs

                device = dev.split('%')[1]
                desc = unquote(str_lookup(inf['strings'], device))

                sec = inf[devmap][dev][0]
                hid = inf[devmap][dev][1]
                sec = sec.lower()

                hid = hid.upper()

                if sec in inf:
                    mainsec = sec
                else:
                    mainsec = fuzzy_lookup(inf.keys(), sec)
                    if mainsec is None: continue

                if mainsec.endswith('.services') and mainsec in inf:
                    serv_sec = mainsec
                elif mainsec + '.services' in inf:
                    serv_sec = mainsec + '.services'
                else:
                    serv_sec = fuzzy_lookup(inf.keys(), mainsec.split('.')[0], '.services')
                    if serv_sec is None:
                        if debug > 0: print(f'Service section for {mainsec} not found, skipping...')
                        continue

                if hid in devices: continue # Multiple sections define same devices

                if dumpdev: print('Desc:', desc)
                if dumpdev: print('hid:', hid)

                tmp = item_lookup(inf[serv_sec], 'addservice')
                if tmp is None:
                    if debug > 0: print(f'Warning: addservice not found {serv_sec}')
                    continue
                service = tmp[0]
                sec_service = tmp[2]

                driver = None
                if (type(inf[mainsec]) == type({})
                    and 'copyfiles' in inf[mainsec]):
                    sec_files = inf[mainsec]['copyfiles'][0].lower()
                    if type(inf[sec_files]) == type([]):
                        driver = inf[sec_files][0]

                if driver is None:
                    if sec_service.lower() not in inf:
                        print(f'Warning missing ServiceBinary for {sec_service}')
                        #print(f'Please report including this file: {filename}\n')
                        continue
                    driver = inf[sec_service.lower()]['ServiceBinary'][0].split('\\').pop()

                if dumpdev: print('Driver', driver)

                try:
                    char = eval(inf[mainsec]['Characteristics'][0])
                except:
                    char = 132

                if dumpdev: print('Characteristics', char)
                try:
                    btype = int(inf[mainsec]['BusType'][0])
                except:
                    try:
                        btype = bustype[hid.split('\\')[0]]
                    except:
                        btype = 0

                if dumpdev: print('BusType', btype)
                if dumpdev: print('Service', service)
                if dumpdev: print('-'*78)


                devices[hid] = { 'desc' : desc,
                                 'char' : str(char),
                                 'btype': str(btype),
                                 'drv'  : driver,
                                 'svc'  : service,
                                 'inf'  : filename.split('/').pop() }
    return devices


if __name__ == '__main__':
    if len(argv) != 2:
        print(f'Usage {argv[0]}: directory_with_infs or inf file')
        sys_exit(-1)

    if isfile(argv[1]):
        filelist = [ argv[1] ]
    else:
        filelist = glob(argv[1] + '/*.inf')

    devlist = {}
    for inffile in filelist:
        if inffile.split('/').pop() not in exclude:
            try:
                devlist.update(scan_inf(inffile))
            except:
                print('--')
                print('Error parsing', inffile)
                #print('Please report sending the inf file and this message:')
                print('---- CUT HERE ----')
                print(f'{argv[0]} Version {__version__}\n')
                print(format_exc())
                print('---- CUT HERE ----')

    print(f'Compiled {len(devlist)} drivers')

    fd = open('devlist.cache', 'wb')
    dump(devlist, fd)
    fd.close()
    print('generated devlist.cache')

    fd = open('nics.txt', 'w')
    drvhash = {}
    for nic, desc in devlist.items():
        entry = nic.split('&')
        if len(entry) < 2: continue # just to be sure
        if not entry[0].startswith('PCI'): continue # skip usb
        vid = entry[0].split('VEN_').pop().lower()
        pid = entry[1].split('DEV_').pop().lower()
        key = (vid, pid)
        line = f'{vid:4} {pid:4} {desc["drv"]} {desc["svc"]}\n'
        drvhash[key] = line

    fd.writelines(sorted(drvhash.values()))
    fd.close()

    print('generated nics.txt')
