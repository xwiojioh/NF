#!/usr/bin/env python3
"""
Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The OpenAirInterface Software Alliance licenses this file to You under
the OAI Public License, Version 1.1  (the "License"); you may not use this file
except in compliance with the License.
You may obtain a copy of the License at

  http://www.openairinterface.org/?page_id=698

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
------------------------------------------------------------------------------
For more information about the OpenAirInterface (OAI) Software Alliance:
  contact@openairinterface.org
---------------------------------------------------------------------
"""

import logging
import re
import sys
import cls_cmd

logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)8s: %(message)s"
)

import argparse
import re

def recreate_entitlements(args):
    namespace = args.namespace
    myCmds = cls_cmd.LocalCmd()
    try:
       ret = myCmds.run(f'oc get project {namespace}')
       if ret.returncode != 0:
          return 1
       myCmds.run(f'oc delete secret etc-pki-entitlement -n {namespace}')
       myCmds.run(f"oc get secret etc-pki-entitlement -n openshift-config-managed -o json |   jq 'del(.metadata.resourceVersion)' | jq 'del(.metadata.creationTimestamp)' |   jq 'del(.metadata.uid)' | jq 'del(.metadata.namespace)' |   oc create -n {namespace} -f -")
       exitcode = 0
    except Exception as e:
       print(f"Exception with reason {e}, in re-creating entitlements in namespace {namespace}")
       exitcode = 1
    myCmds.close()
    return exitcode

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-n', '--namespace', default='oaicicd-core', help="Kubernetes namespace name")
        parser.set_defaults(func=recreate_entitlements)
        args = parser.parse_args()
        rc = args.func(args)
        print("Execution finished, exiting with code {}".format(str(rc)))
        sys.exit(rc)
    except Exception as e:
        print("main() caught exception %s" %(str(e)))
        sys.exit(1)

if __name__ == "__main__":
    main()
