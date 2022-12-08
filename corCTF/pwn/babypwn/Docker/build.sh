#!/bin/bash
docker rm -f babypwn
docker build --tag=babypwn . && \
docker run -p 9002:9002 --privileged=true --restart=on-failure --name=babypwn --detach babypwn