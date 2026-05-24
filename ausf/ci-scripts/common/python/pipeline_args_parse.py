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

import argparse
import re

def _parse_args() -> argparse.Namespace:
    """Parse the command line args

    Returns:
        argparse.Namespace: the created parser
    """
    example_text = '''example:
        ./generateHtmlReport.py --help'''

    parser = argparse.ArgumentParser(description='OAI 5G CORE NETWORK Utility tool',
                                    epilog=example_text,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)

    # Pipeline Name
    parser.add_argument(
        '--job-name', '-jn',
        action='store',
        help='Pipeline name',
    )

    # Build Number
    parser.add_argument(
        '--build-id', '-id',
        action='store',
        help='Build ID or number',
    )

    # Build URL
    parser.add_argument(
        '--build-url',
        action='store',
        help='Build URL',
    )

    # GIT repo URL
    parser.add_argument(
        '--git-url',
        action='store',
        help='GIT repo URL',
    )

    # GIT source branch
    parser.add_argument(
        '--git-src-branch',
        action='store',
        help='GIT source branch',
    )

    # GIT source commit
    parser.add_argument(
        '--git-src-commit',
        action='store',
        help='GIT source commit (SHA-ONE)',
    )

    # GIT MR or PR
    parser.add_argument(
        '--git-merge-request',
        action='store_true',
        default=False,
        help='GIT source commit (SHA-ONE)',
    )

    # GIT destination branch
    parser.add_argument(
        '--git-dst-branch',
        action='store',
        help='GIT destination branch',
    )

    # GIT destination commit
    parser.add_argument(
        '--git-dst-commit',
        action='store',
        help='GIT destination commit (SHA-ONE)',
    )

    args, unknown = parser.parse_known_args()
    return args
