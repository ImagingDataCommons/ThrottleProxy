#!/usr/bin/env bash

if [ -n "$CI" ]; then
    # Note that CIRCLE_PROJECT_REPONAME is a Circle CI built-in var:
    export HOME=/home/circleci/${CIRCLE_PROJECT_REPONAME}
    export HOMEROOT=/home/circleci/${CIRCLE_PROJECT_REPONAME}
else
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
    exit
fi

# Remove .pyc files; these can sometimes stick around and if a
# model has changed names it will cause various load failures
find . -type f -name '*.pyc' -delete

# Install and update apt-get info
echo "Preparing System..."
apt-get -y install software-properties-common
apt-get update -qq

#
# Needed due to CircleCI changes: dropping CA certs?

apt-get install ca-certificates

# Install apt-get dependencies
echo "Installing Dependencies..."
apt-get install -y --force-yes unzip libffi-dev libssl-dev python3-dev libpython3-dev git ruby g++ curl dos2unix python3.5
echo "Dependencies Installed"

# Install PIP + Dependencies
echo "Installing pip3..."
curl --silent https://bootstrap.pypa.io/get-pip.py | python3

# Install our primary python libraries
# If we're not on CircleCI, install the libraries
if [ -z "${CI}" ]; then
    echo "Installing Python Libraries..."
    pip3 install -r ${HOMEROOT}/requirements.txt -t ${HOMEROOT}/lib --upgrade --only-binary all
else
    echo "CircleCI deployment detected - Google AppEngine will handle requirements.txt"
fi

echo "Libraries Installed"

# Install Google Cloud SDK
# If we're not on CircleCI or we are but google-cloud-sdk isn't there, install it
if [ -z "${CI}" ] || [ ! -d "/usr/lib/google-cloud-sdk" ]; then
    echo "Installing Google Cloud SDK..."
    export CLOUDSDK_CORE_DISABLE_PROMPTS=1
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    apt-get install apt-transport-https ca-certificates
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
    apt-get update && apt-get -y --allow-downgrades install google-cloud-sdk=251.0.0-0
    apt-get -y --allow-downgrades install google-cloud-sdk-app-engine-python=251.0.0-0
    echo "Google Cloud SDK Installed"
fi




