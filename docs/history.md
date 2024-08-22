# 更新记录

| Version| Date      | Description | Author      |
|--------|-----------|-------------|-------------|
| v4.0   | 2023-5-2  | Maat 4.0, reorganize documentation using Markdown  | Zheng Chao, Liu Wentan |
| v3.7.0 | 2022-8-23 | Add Boolean Expression callback table; correct descriptions of grouping within subgroups| Zheng Chao|
| v3.2.3 | 2021-7-15 | Add section on composite scanning  | Zheng Chao  |
| v3.1.20| 2021-4-28 | Add explanation for loading gzip-compressed JSON files | Zheng Chao  |
| v3.1.5 | 2021-3-12 | Add matching examples for callback class FQDN table | Zheng Chao  |
| v3.1.4 | 2020-11-04| When content foreign key is "null," it represents an empty file   | Zheng Chao  |
| v3.1.1 | 2020-9-27 | Add explanation for creating attributes on multiple different types of physical tables | Zheng Chao  |
| v3.1.0 | 2020-9-18 | Add FQDN callback table | Zheng Chao  |
| v3.0.4 | 2020-8-17 | Add extended numerical domain configuration interval_plus  | Zheng Chao  |
| v3.0   | 2020-6-29 | Maat 3.0, support clauses, original grouping table split into grouping relationship table and grouping compilation table | Zheng Chao  |
| v2.8   | 2020-3-13 | Support composite tables   | Zheng Chao  |
| v2.8   | 2020-2-11 | Support Hit Path  | Zheng Chao  |
| v2.8   | 2020-2-4  | Support sorting strategies by Evaluation Order  | Zheng Chao  |
| v2.8   | 2020-1-22 | Maat JSON file encryption support, see 17.3   | Zheng Chao  |
| v2.8   | 2019-7-28 | 1. No longer compatible with no grouping tables  2. Support attributes | Zheng Chao  |
| v2.7.2 | 2019-7-10 | Expand IP configuration table to support CIDR format | Zheng Chao  |
| v2.7.1 | 2019-5-23 | Rename rich IP class configuration table to extended IP configuration table  | Zheng Chao  |
| v2.7.0 | 2019-5-12 | 1. Add explanation for subgroup relationships  2. Add explanation for rich IP class configuration | Zheng Chao  |
| v2.6.0 | 2019-1-8  | 1. Add explanation for "not" operation  2. Document and dynamic link library version numbers share the first two digits | Zheng Chao  |
| v2.3.3 | 2018-12-24| Add explanation for Extra Data and read column function; in multiple hit scenarios, return results in descending order of configuration ID | Zheng Chao  |
| v2.3.2 | 2018-12-03| Support runtime loading of changing JSON files in full notification mode | Zheng Chao  |
| v2.3.1 | 2018-10-15| Improve explanation of content foreign keys and configuration effective tags | Zheng Chao  |
| v2.3.0 | 2018-9-26 | Add explanation of content foreign keys and configuration effective tags | Zheng Chao  |
| v2.2.5 | 2018-9-12 | Correct explanation of IP domain configuration regarding all 0 masks representing any to exact match | Zheng Chao  |
| v2.2.4 | 2018-08-09| In "Configuration Table Description Files" section, explain how to set custom domain transcoding in compilation configuration table | Zheng Chao  |
| v2.2.3 | 2018-07-27| 1. Enhance "Common Fault Handling -> Scan Results Inconsistent" section  2. Organize "Configuration Description Methods" section | Zheng Chao  |
| v2.2.2 | 2018-07-05| Support user-defined domains exceeding 128 bytes | Zheng Chao  |
| v2.2.1 | 2018-05-25| Update transaction mechanism for loading Redis configuration interface   | Zheng Chao  |
| v2.1.2 | 2018-03-24 | Add overview    | Zheng Chao  |
| v2.1.1 | 2018-02-08 | 1. maat_redis_tool supports writing JSON format configurations to Redis  2. Add instructions for using Maat_read_state function | Zheng Chao  |
| v2.1.0 | 2017-10-04 | Provide maat_redis_tool to dump Maat configurations from Redis   | Zheng Chao  |
| v2.0.1 | 2017-08-22 | Support delayed initialization for configurations  | Zheng Chao  |
| v2.0.0 | 2017-08-01 | 1. Support loading configurations from Redis;  2.Provide configuration add and delete function interfaces, i.e., Maat Command API;  3.Support similarity string matching;  4.Provide auxiliary tool digest_gen, with SFH digest calculation and edit distance calculation functions. | Zheng Chao  |
| v1.9.1 | 2017-06-24 | Can prompt the last domain in MAAT combination scan, which can improve performance with expression operations. | Zheng Chao  |
| v1.9.0 | 2017-06-09 | Support encryption for individual configuration tables  | Zheng Chao |
| v1.8.4 | 2017-03-12 | Adjust the directory structure of SNORT rule conversion  | Zheng Chao |
| v1.8.3 | 2016-12-30 | 1. Add the functionality to set the instance name; 2. Update the explanation of running status data. | Zheng Chao         |
| v1.8.2 | 2016-9-19  | JSON input mode supports unnamed groups, where group_name can be configured as "Untitled" to indicate non-group reuse, and Maat automatically generates group_id. | Zheng Chao         |
| v1.8.1 | 2016-9-14  | Add guidance for nested IP matching in IP class domain configuration tables. | Zheng Chao         |
| v1.8.0 | 2016-09-02 | Add explanation for configuration table connections   | Zheng Chao         |
| v1.7.1 | 2016-06-17 | 1. Support spaces as keywords through escape mode;  2. Add a switch for fast string scanning; | Zheng Chao      |
| v1.7.0  | 2016-04-03 | Add a section describing encoding conversion, and include instructions for UNICODE to ASCII transcoding functionality.     | Zheng Chao         |
| v1.6.1  | 2016-03-24 | Improve the field description of configuration group tables.  | Zheng Chao |
| v1.6.0  | 2016-02-11 | 1.    Add descriptions for status and performance statistics, and adjust corresponding function interfaces;  2.    Add function interface descriptions for extended string class domain configurations. | Zheng Chao         |
| v1.5.0  | 2016-01-05 | Add extended string class domain configurations, and enhance descriptions for IPv6 mask in IP class domain configurations. | Zheng Chao         |
| v1.4.4  | 2015-12-24 | Modify the configuration update mechanism for callback tables to save memory. | Zheng Chao         |
| v1.4.3  | 2015-12-02 | Improve descriptions of database table relationships and enrich interface design points. | Zheng Chao         |
| v1.4.2  | 2015-12-01 | Merge the chapter on configuration update file interfaces. | Zheng Chao  |
| v1.4.1  | 2015-11-23 | Improve descriptions for summary class configurations | Zheng Chao |
| v1.4.0  | 2015-11-06 | Add file summary class domain configurations | Zheng Chao         |
| v1.3.9  | 2015-07-24 | Provide Maat_set_feather_opt interface, supported in versions Maat_20150724 and above. | Zheng Chao |
| v1.3.8  | 2015-07-06 | Refine explanations of the three types of configurations in the overview, and add explanations for encoding handle reuse.     | Zheng Chao         |
| v1.3.7  | 2015-06-16 | Add suggestions for common fault handling.| Zheng Chao         |
| v1.3.6  | 2015-06-10 | 1. Add expression types for relative positions to string domain tables;  2. Support non-testing branches in configuration group tables, not yet merged into the main version. | Zheng Chao         |
| v1.3.5  | 2015-06-08 | Add examples for database table descriptions | Zheng Chao         |
| v1.3.4  | 2015-05-22 | Load callback class configurations through JSON | Zheng Chao |
| v1.3.3  | 2015-05-13 | Add fast processing path for non-combined domain compilation, and explain conditions for returning hit results. | Zheng Chao  |
| v1.3.2  | 2015-04-13 | Change return value for scanning empty configurations from -1 to 0 | Zheng Chao         |
| v1.3.1  | 2015-03-02 | Change source encoding for GBK to BIG5 transcoding to GB2312 | Zheng Chao|
| v1.3    | 2015-02-20 | Add JSON configuration loading functionality | Zheng Chao  |
| v1.2.2  | 2015-01-06 | Add forced unloading mechanism | Zheng Chao         |
| v1.2.1  | 2015-01-05 | Extend definition of hexbin field for string class domain configurations | Zheng Chao         |
| v1.2.0  | 2014-12-20 | Add description for configuration update mechanism | Zheng Chao |
| v1.1.0  | 2014-12-12 | Add descriptions for function interfaces, and modify reference counting to avoid false sharing | Zheng Chao         |
| v1.0.3  | 2014-12-03 | Use garbage collection mechanism to ensure thread safety | Zheng Ch|
| v1.0.2  | 2014-11-26 | Support regular expression grouping | Zheng Chao  |
| v1.0.1  | 2014-11-19 | IP scanning supports protocol parameter | Zheng Chao  |
| v1.0    | 2014-08-19 | First stable version  | Zheng Chao  |
| v0.1    | 2014-06-16 | Create document and define table format | Zheng Chao  |