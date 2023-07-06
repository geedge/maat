 依赖 crypto库，需提前安装
 安装 redis-server 并按默认配置启动即可，maat_demo_gtest 会用到 redis

## 编译 & 运行单测
1. 当前目录，mkdir build
2. cd build
3. cmake ..
4. make
5. ./maat_demo_gtest

## 文件说明：

- include 目录存放 maat 库头文件
- lib 目录存放 maat 动态库及 gtest 静态库
- testdata 为单测所需测试数据
- maat_demo.json 为json 格式的匹配规则，运行时会转为 iris 格式，位于maat_demo.json_iris_tmp目录(运行时生成)
- demo_table_info.conf用于表示 iris 格式规则每列代表的含义，maat解析对应列的数据
- maat_demo_gtest.cpp 为单测文件，字符串匹配相关测试用例可供参考