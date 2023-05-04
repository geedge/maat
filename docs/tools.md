# Tools

## maat_redis_tool工具

可以将redis中的生效配置dump为本地IRIS格式的配置文件，即文件配置加载接口所描述的格式。

可以将json格式的配置写入redis。注意：该模式下不支持分组复用。

具体用法，参照./maat_redis_tool  -? 的输出。

## digest_gen工具

可以计算文件的SFH摘要，比较两个SFH摘要的相似度，比较普通字符串的相似度。

具体用法，参照./digest_gen –? 的输出。

## 使用gzip命令压缩JSON配置

Maat_set_feather_opt的MAAT_OPT_JSON_IS_GZIPPED参数可以压缩后的规则文件。

```shell
[zhengchao@GDNT-BJ-DEV1 ~]$ gzip -9 < maat_json.json > maat_json.json.gz
```

可以和下面的加密命令联合使用，应**先压缩后加密**。

## 使用openssl enc对配置加解密

Maat_set_feather_opt的MAAT_OPT_DECRYPT_KEY参数可以加载加密的规则文件，文件可以通过命令行进行加解密（openssl 版本小于 v1.1.0）。

加密：

```shell
[zhengchao@GDNT-BJ-DEV1 ~]$ openssl enc -e -aes-128-cbc -k 123456 -p  -nosalt -in inputfile.txt -out encryptfile.txt  
```

解密：

```
[zhengchao@GDNT-BJ-DEV1 ~]$ openssl enc -d -aes-128-cbc -k 123456 -p -nosalt -in encryptfile.txt -out tmp.txt 
```

原理参见：https://blog.csdn.net/littlefang/article/details/72972266