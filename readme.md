# 简介
MAAT是古埃及神话中真理与正义女神，她的羽毛（feather）能够判断离世之人能否前往天堂。 

MAAT框架对网络流处理中的配置进行抽象，并具有配置写入、多机同步（基于Redis）、加载、扫描的功能。

maat.h中描述了初始化和配置扫描的API。 

maat_command.h中描述了配置写入的API。 

# 编译
普通编译

` Make`

带调试符号编译

`Make debug`

安装

`Make install`

生成动态链接库 `./build/src/libmaat4.so`

生成静态链接库 `./build/src/libmaat4.a`