#!/usr/bin/env bash

MY_VENV="Your python virtual environment"
INSTALL_LIBS="TRUE or FALSE"
CONFIG_FILE="Location of config.txt"

ENV_FILE="./run-proxy-SetEnv.sh"
if [ -f "${ENV_FILE}" ]; then
    source "${ENV_FILE}"
fi

if [ "${INSTALL_LIBS}" = "TRUE" ]; then
  pushd ${MY_VENV} > /dev/null
  source bin/activate
  popd > /dev/null
  echo "Installing Python Libraries..."
  python3 -m pip install -r ../requirements.txt
fi

#
# For desktop operations
#

export PYTHONPATH=${MY_VENV}/lib
export IDC_THROTTLE_PROXY_CONFIG=${CONFIG_FILE}

pushd ${MY_VENV} > /dev/null
source bin/activate
popd > /dev/null
cd ..
python3 ./main.py
deactivate
