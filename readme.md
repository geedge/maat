# MAAT网络流处理配置统一描述框架   

## 简介

MAAT是古埃及神话中真理与正义女神，她的羽毛（feather）能够判断离世之人能否前往天堂。 

MAAT框架对网络流处理中的配置进行抽象，并具有配置写入、多机同步（基于Redis）、加载、扫描的功能。

MAAT的输入可以选择三种输入源：

* Redis数据库，用于生产环境，由其它程序写入，数据源通常为关系数据库，如Oracle、MySQL；也可以通过Maat Command API写入。
* JSON文件，用于生产环境和调试，支持支持动态加载。
* Tab分割的文本文件（IRIS），故障诊断用。

maat.h中描述了初始化和配置扫描的API。 

maat_command.h中描述了配置写入的API。 

## 编译
普通编译

` Make`

带调试符号编译

`Make debug`

安装

`Make install`

生成动态链接库 `./build/src/libmaat4.so`

生成静态链接库 `./build/src/libmaat4.a`

## 更多资料

[Introduction](./docs/introduction.md) 概念和原理

[Table Schema](./docs/table_schema.md) 配置表的模式

[Table Data](./docs/table_data.md) 配置表中的数据

[Scan API](./docs/scan_api.md) 扫描接口

[Tools](./docs/tools.md) 工具

