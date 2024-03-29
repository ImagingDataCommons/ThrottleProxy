#!/usr/bin/env bash

#
# For desktop operations
#

source ./setEnvVars.sh

export PYTHONPATH=${MY_VENV}/lib
export IDC_THROTTLE_PROXY_CONFIG=${MY_VENV}/config.txt

pushd ${MY_VENV} > /dev/null
source bin/activate
popd > /dev/null
cd ..
python3 ./main.py
deactivate
