#!/usr/bin/env python3
"""Install only the generated isolated demo app; explicit --restart is optional.

Requires write access to the selected local Splunk installation. Does not touch
other apps, authentication configuration, or existing indexes. No AWS calls.
"""
import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from build_change_app import APP, APP_ID, RULE_NAME
from change_scenario import DATA


def install(home,owner,update=False,restart=False):
    home=Path(home).resolve()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',owner):raise ValueError('invalid local Splunk user name')
    if not (home/'bin/splunk').is_file():raise ValueError('not a Splunk Enterprise installation')
    destination=home/'etc/apps'/APP_ID
    marker=destination/'gss_demo_install.json'
    if destination.exists() and not (update and marker.is_file()):
        raise ValueError('destination exists; refuse overwrite without --update and our install marker')
    if not (APP/'default/savedsearches.conf').exists():raise ValueError('build the app first')
    shutil.copytree(APP,destination,dirs_exist_ok=update)
    (destination/'local').mkdir(exist_ok=True)
    shutil.copyfile(DATA/'install_overlay/inputs.conf',destination/'local/inputs.conf')
    # Bind only this app's schedule to an explicitly identified existing user.
    meta=destination/'metadata/local.meta'
    meta.write_text(f'[savedsearches/{RULE_NAME}]\nowner = {owner}\naccess = read : [ admin ], write : [ admin ]\nexport = none\n')
    marker.write_text(json.dumps({'app_id':APP_ID,'owner':owner,'source':str(APP),'synthetic_only':True},indent=2)+'\n')
    check=subprocess.run([str(home/'bin/splunk'),'cmd','btool','check','--app='+APP_ID],capture_output=True,text=True)
    print(check.stdout,check.stderr,sep='')
    if check.returncode:raise RuntimeError('btool rejected configuration; do not restart until corrected')
    print('Installed isolated app:',destination,flush=True)
    if restart:
        print('Restarting this local Splunk service to load the new app, indexes and file inputs.',flush=True)
        result=subprocess.run([str(home/'bin/splunk'),'restart'])
        if result.returncode:raise RuntimeError('restart did not complete; preserve files and inspect service output')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--splunk-home',required=True)
    parser.add_argument('--owner',required=True)
    parser.add_argument('--update',action='store_true')
    parser.add_argument('--restart',action='store_true')
    args=parser.parse_args()
    install(args.splunk_home,args.owner,args.update,args.restart)


if __name__=='__main__':main()
