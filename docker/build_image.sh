#!/bin/bash
docker build -t cyf/signserver:22.04 -f ubuntu22.04/Dockerfile .
docker-compose up -d