#!/usr/bin/env bash

#
# Desktop dependency installer
#

source ./setEnvVars.sh

export PYTHONPATH=${MY_VENV}/lib

pushd ${MY_VENV} > /dev/null
source bin/activate
popd > /dev/null
cd ..
mkdir -p lib
python3 -m pip install -r requirements.txt -t ${MY_VENV}/lib
deactivate
