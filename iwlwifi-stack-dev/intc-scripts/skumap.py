#!/usr/bin/env python3

import jira, pwd, os, sys
from getpass import getpass
from pathlib import Path

this_dir = Path(__file__).absolute().parent
skumap_c_in = this_dir/"skumap.c"
driver_dir = this_dir.parent
tests_dir = driver_dir/"drivers"/"net"/"wireless"/"intel"/"iwlwifi"/"tests"
skumap_c = tests_dir/"skumap.c"
skumap_h = tests_dir/"skumap.h"
makefile = tests_dir/"Makefile"

try:
    os.symlink(skumap_c_in, skumap_c)
except FileExistsError:
    pass

with open(makefile, 'r') as mf:
    if not 'skumap.o' in mf.read():
        with open(makefile, 'a') as mf:
            mf.write('\n\n')
            mf.write('iwlwifi-tests-y += skumap.o\n')

username = os.environ.get('JIRA_USER')
password = os.environ.get('JIRA_PASS')
if not username:
    username = pwd.getpwuid(os.getuid()).pw_name
    print(f"Username [{username}]: ", end='', file=sys.stderr)
    inp = input()
    if inp:
        username = inp
    password = getpass()

conn = jira.JIRA(server='https://jira.idoc.intel.com/',
                 basic_auth=(username, password),
                 options={'verify': False})

fields = {
    f['id']: f['name'] for f in conn.fields()
}

skus = conn.search_issues('project=SKUMAP and type=SKU and status=LOCKED',
                          maxResults=False)
out = {}
skumap = {}
out['skus'] = skumap
for sku in skus:
    data = {}
    for k, v in sku.raw['fields'].items():
        n = fields.get(k, k)
        data[n] = v
    skumap[sku.key] = data

platforms = conn.search_issues('project=SKUMAP and type=Platform and status=LOCKED',
                               maxResults=False)
platformmap = {}
out['platforms'] = platformmap
for platform in platforms:
    data = {}
    for k, v in platform.raw['fields'].items():
        n = fields.get(k, k)
        data[n] = v
    platformmap[platform.key] = data


def val_string(v):
    if v is None:
        return ''
    if isinstance(v, dict):
        return v['value']
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return '|'.join(val_string(x) for x in v)
    assert False, repr(v)

def force_hex(k, v):
    if v is None:
        return ''
    v = v.lower()
    if not v.startswith('0x'):
        return '0x' + v
    return v

def must_hex(k, v):
    v = val_string(v).lower()
    if v == 'na': return '0'
    assert v.startswith('0x'), f"{k}: {v}"
    return v

def boolean(k, v):
    v = val_string(v).lower()
    assert v in ('yes', 'no'), f"{k}: {v}"
    return 'true' if v == 'yes' else 'false'

def chains(k, v):
    v = val_string(v).lower()
    assert v in ('1x1', '2x2')
    return '2' if v == '2x2' else '1'

def string(k, v):
    return f'"{val_string(v)}"'

def special_regulatory(k, v):
    v = val_string(v)
    if not v:
        return 'NONE'
    return v.replace(' ', '_')

keys = {
    'WIFI PCI Vendor ID': force_hex,
    'WIFI PCI Device ID' : force_hex,
    'WIFI PCI Sub Vendor ID': force_hex,
    'WIFI PCI Sub system ID': force_hex,
    'SKU Type': lambda k,v: val_string(v),
    'PHY ID': must_hex,
    'PHY Step': must_hex,
    'PHY flavor': must_hex,
    'PHY dash': must_hex,
    'PHY jacket': boolean,
    'PHY CDB': boolean,
#    'CNVI Name',
    'WIFI Chains': chains,
#    'Environment',
    'MAC ID': must_hex,
    'MAC step': force_hex,
    'Regulatory': lambda k,v: val_string(v),
    'Regulatory Special Settings': special_regulatory,
#    'Product acronym': lambda k,v: val_string(v),
    'jira': string,
#    'Include INF', # seems useless
    'WIFI Product Name in INF': string,
}

def sort_key(k):
    assert k.startswith('SKUMAP-')
    return int(k[7:])

with open(skumap_h, 'w') as outf:
    def wline(l):
        outf.write(l)
        outf.write('\n')

    wline('\t// DEVICE(' + (', '.join(keys.keys())) + ')')
    for sku_key, sku in sorted(out['skus'].items(), key=lambda k: sort_key(k[0])):
        for link in sku['Linked Issues']:
            if not 'type' in link or not 'outwardIssue' in link:
                continue
            if link['type']['outward'] != 'Appears in Product':
                continue
            plat_key = link['outwardIssue']['key']
            try:
                platform = out['platforms'][plat_key]
            except KeyError:
                wline(f"\t// skip platform {plat_key} - not LOCKED")
                continue
            if val_string(platform['MAC ID']).lower() == 'tbd':
                wline(f"\t// skip platform {plat_key} - no MAC ID")
                continue

            dat = sku.copy()
            dat['WIFI PCI Vendor ID'] = platform['WIFI PCI Vendor ID']
            dat['WIFI PCI Device ID'] = platform['WIFI PCI Device ID']
            dat['PHY jacket'] = platform['PHY jacket']
            dat['MAC ID'] = platform['MAC ID']
            dat['MAC step'] = platform['MAC step']
            dat['jira'] = f"{plat_key} / {sku_key}"

            wline('\tDEVICE(' + (', '.join((m(k, dat[k]) for k, m in keys.items())) + f'), // {sku_key}'))
