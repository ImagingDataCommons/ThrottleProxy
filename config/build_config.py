# Copyright 2015-2020, Institute for Systems Biology.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Do not use environment variables. We use a secrets file and load our own dictionary:
#


import os

def read_dict(my_file_name):
    if not my_file_name:
        my_file_name = os.environ.get('IDC-THROTTLE-PROXY-CONFIG')
    if not my_file_name:
        my_file_name = 'config.txt'
    retval = {}
    with open(my_file_name, 'r') as f:
        for line in f:
            if '=' not in line:
                continue
            split_line = line.split('=')
            retval[split_line[0].strip()] = split_line[1].strip()
    return retval