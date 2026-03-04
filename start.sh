#!/bin/bash

memcached -d -l 127.0.0.1 -p 11211 2>/dev/null || true

sleep 1

go build -o /tmp/yopass-server /home/runner/workspace/cmd/yopass-server/
/tmp/yopass-server --database memcached --memcached localhost:11211 --port 1337 --address localhost &

cd /home/runner/workspace/website && npm run dev
