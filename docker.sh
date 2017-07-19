#!/bin/bash
#
# Generic script for launch the ndeploy docker image
# @author Eric Fehr (ricofehr@nextdeploy.io, github: ricofehr)


#################### CHANGE THIS 3 VALUES WITH YOUR NEXTDEPLOY AUTH INFOS
USERNAME='usera@os.nextdeploy'
PASSWORD='word123123'
ENDPOINT='api.nextdeploy.local'
####################

# Prepare the setting file
if [[ ! -d ~/.nextdeploy ]]; then
  mkdir -p ~/.nextdeploy
  echo "email: $USERNAME" > ~/.nextdeploy/nextdeploy.conf
  echo "password: $PASSWORD" >> ~/.nextdeploy/nextdeploy.conf
  echo "endpoint: $ENDPOINT" >> ~/.nextdeploy/nextdeploy.conf
fi

# Get last docker image
if [[ ! -f /tmp/.ndeploy ]]; then
  docker pull nextdeploy/ndeploy >/dev/null 2>&1
  touch /tmp/.ndeploy
fi

# Launch the container
docker run --rm -v ~/.ssh:/home/app/.ssh -v ~/.nextdeploy:/nextdeploy -v $PWD:/app -t -i nextdeploy/ndeploy $*
