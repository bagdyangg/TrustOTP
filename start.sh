#!/bin/bash

go build -o /tmp/yopass-server /home/runner/workspace/cmd/yopass-server/
/tmp/yopass-server --redis redis://localhost:6379/0 --port 1337 --address localhost &

cd /home/runner/workspace/website && npm run dev
