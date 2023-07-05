# Tools

## maat_redis_tool
1. Dump the configuration in redis to a local IRIS format file.

2. Write the configuration in JSON format to redis. Note: Group multiplexing is not supported in this mode.

For specific usage, run ./maat_redis_tool -h

## compress JSON configuration using gzip command

```shell
$ gzip -9 < maat_json.json > maat_json.json.gz
```

maat_options_set_json_file_gzip_flag can indicate whether maat instance needs to decompress the json configuration before loading it. This API can be used in conjunction with the encryption command below, compressed first and then encrypted.

## using openssl enc to encrypt/decrypt configuration

maat_options_set_json_file_decrypt_key can specify the decryption key for the JSON file to be decrypted.

encrypt：

```shell
$ openssl enc -e -aes-128-cbc -k 123456 -p  -nosalt -in inputfile.txt -out encryptfile.txt  
```

decrypt：

```shell
$ openssl enc -d -aes-128-cbc -k 123456 -p -nosalt -in encryptfile.txt -out tmp.txt 
```