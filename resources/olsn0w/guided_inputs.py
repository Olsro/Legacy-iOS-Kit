"""Acquire selected-device inputs using the Kit's signing and modem tools."""
import json
from pathlib import Path
import platform
import plistlib
import subprocess

from common import KIT, MODELS, digest, integer, tools
from firmware import releases, select_release
from tickets import binding


def tool(name):
    result=tools()/name
    if not result.is_file() and platform.system()=='Darwin':result=KIT/'bin/macos'/name
    if not result.is_file():raise ValueError('Missing Legacy iOS Kit tool: '+name)
    return result


def ticket(identity, destination):
    destination=Path(destination);destination.mkdir(mode=0o700)
    product=identity['product']
    manifest=KIT/'resources/manifest'/('BuildManifest_'+product+'_8.4.1.plist')
    if not manifest.is_file():raise ValueError('Missing signed-base manifest')
    command=[tool('tsschecker'),'-d',product,'-i','8.4.1','-e',str(identity['ecid']),
             '-m',manifest,'-o','-s','-B',identity['board'],'-b','-g','0x1111111111111111']
    with (destination/'request.log').open('wb') as log:
        result=subprocess.run(list(map(str,command)),cwd=destination,stdout=log,stderr=subprocess.STDOUT,timeout=180)
    if result.returncode:raise RuntimeError('Apple signing request failed; no device was erased. See '+str(destination/'request.log'))
    matches=[]
    for path in destination.glob('*.shsh*'):
        binding(path.read_bytes(),product,identity['ecid'])
        matches.append(path)
    if len(matches)!=1:raise ValueError('Signing request did not produce one matching ticket')
    return matches[0]


def modem(identity, destination):
    if identity['product']=='iPad3,4':return None,None
    destination=Path(destination);destination.mkdir(mode=0o700)
    product=identity['product'];board,chip,board_id=MODELS[product]
    record=select_release(releases(product),'10.3.4','14G61')
    name='Mav5-11.80.00.Release.bbfw'
    for member in ('BuildManifest.plist','Firmware/'+name):
        with (destination/(Path(member).name+'.log')).open('wb') as log:
            result=subprocess.run([str(tool('pzb')),'-g',member,record['url']],cwd=destination,
                                  stdout=log,stderr=subprocess.STDOUT,timeout=600)
        if result.returncode:raise RuntimeError('Could not obtain the selected modem firmware')
    manifest=destination/'BuildManifest.plist'
    data=plistlib.loads(manifest.read_bytes())
    matches=[i for i in data['BuildIdentities'] if i['Info']['DeviceClass']==board
             and integer(i['ApChipID'])==chip and integer(i['ApBoardID'])==board_id]
    if data['ProductBuildVersion']!='14G61' or product not in data['SupportedProductTypes'] or not matches:
        raise ValueError('Modem manifest differs from the selected device')
    file=destination/name
    if not file.exists():file=destination/'Firmware'/name
    if digest(file,'sha1')!='8951cf09f16029c5c0533e951eb4c06609d0ba7f':raise ValueError('Modem checksum mismatch')
    if not any(Path(i['Manifest']['BasebandFirmware']['Info']['Path']).name==name for i in matches):
        raise ValueError('Modem component differs from its manifest')
    return file,manifest
