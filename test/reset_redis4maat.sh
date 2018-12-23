#!/bin/sh
host="127.0.0.1"
port="6379"
db="0"
echo "Reseting Redis For Maat..."
redis-cli -h $host -p $port -n $db GET MAAT_VERSION
redis-cli -h $host -p $port -n $db FLUSHALL
redis-cli -h $host -p $port -n $db SET MAAT_VERSION "0"
redis-cli -h $host -p $port -n $db SET MAAT_PRE_VER "0"
redis-cli -h $host -p $port -n $db SET SEQUENCE_REGION "1"
redis-cli -h $host -p $port -n $db SET SEQUENCE_GROUP "1"
