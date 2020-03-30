#!/usr/bin/env bash


source ./setEnvVars.sh

export PYTHONPATH=${MY_VENV}/lib:.
export GOOGLE_APPLICATION_CREDENTIALS=${MY_VENV}/sa-key.json
export IDC_THROTTLE_PROXY_CONFIG=${MY_VENV}/test-config.txt

pushd ${MY_VENV} > /dev/null
source bin/activate
popd > /dev/null
cd ..
python3 test/test_prox.py
deactivate
