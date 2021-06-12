#!/bin/sh

if [ -z "$1" ]; then
  echo "Missing container name.  Usage: docker-deploy.sh <container-name>"
else
  docker run -dp 1965:1965 \
    --name $1 \
    --mount source=moongem-content,target=/gemini \
    --mount source=moongem-certs,target=/certs,readonly \
    moongem
fi
