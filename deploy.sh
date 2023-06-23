#!/bin/sh

docker build -t murphylan/formlogin .  
docker run -d --name formlogin -p 8080:8080 murphylan/formlogin