#!/bin/bash
#
# Generic script for launch the ndeploy docker image
# @author Eric Fehr (ricofehr@nextdeploy.io, github: ricofehr)

USERNAME='usera@os.nextdeploy'
PASSWORD='word123123'
ENDPOINT='api.nextdeploy.local'

mkdir -p ~/.nextdeploy
echo "email: $USERNAME" > ~/.nextdeploy/nextdeploy.conf
echo "password: $PASSWORD" >> ~/.nextdeploy/nextdeploy.conf
echo "endpoint: $ENDPOINT" >> ~/.nextdeploy/nextdeploy.conf

docker pull nextdeploy/ndeploy >/dev/null 2>&1
docker run --rm -v ~/.ssh:/var/www/.ssh -v ~/.nextdeploy:/nextdeploy -v $PWD:/app -t -i nextdeploy/ndeploy $*
