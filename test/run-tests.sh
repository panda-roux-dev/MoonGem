#!/bin/sh

if [ -d "./env" ]; then

  # build moongem if it's not built already
  mkdir -p ../build
  pushd ../build
  cmake -DCMAKE_BUILD_TYPE=Release ..
  make -j moongem
  popd

  # run the server and fork
  ../build/moongem -p 1966 -c cert.pem -k key.pem -r root/ >/dev/null &
  mgpid=$!

  echo "Server PID: $mgpid"

  # run test script
  source env/bin/activate
  python test.py
  deactivate

  # kill the server
  kill -s TERM $mgpid
else
  echo "Run setup.sh first in order to configure the testing environment."
fi
