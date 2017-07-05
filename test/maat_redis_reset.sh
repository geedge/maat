#!/bin/sh
host="127.0.0.1"
port="6379"
echo "Reset Redis For Maat Starting"
redis-cli -h $host -p $port GET MAAT_VERSION
redis-cli -h $host -p $port FLUSHALL
redis-cli -h $host -p $port SET MAAT_VERSION 0
redis-cli -h $host -p $port SET SEQUENCE_REGION 0
redis-cli -h $host -p $port SET SEQUENCE_GROUP 0

