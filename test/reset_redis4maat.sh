#!/bin/sh
host="127.0.0.1"
port="6379"
echo "Reseting Redis For Maat..."
redis-cli -h $host -p $port GET MAAT_VERSION
redis-cli -h $host -p $port FLUSHALL
redis-cli -h $host -p $port SET MAAT_VERSION "1"
redis-cli -h $host -p $port SET SEQUENCE_REGION "1"
redis-cli -h $host -p $port SET SEQUENCE_GROUP "1"

