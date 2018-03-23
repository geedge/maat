Author:Zheng Chao zhengchao@iie.ac.cn
2014-04-01 create this project;
2014-08-19 first online version;
2014-09-09 support expr offset;
2014-09-26 add group function;
2014-12-03 support regex grouping;
2014-12-17 write some comments in Maat_rule.h;
2014-12-22 add group_num in compile config table;
2015-01-04 make string match not case sensitive,fix garbage_bagging malloc wrong size bug;
2015-01-07 replace assert of database rule format,unescape '&' of EXPR_TYPE_OFFSET;
2015-01-22 ouput IRIS index file format error;verify string scan input data
and data len;
2015-01-28 enfore parameter check in Maat_stream_scan_string_detail to
optimize performance;
2015-02-04 support stream scan data with offset;
2015-02-20 add JSON config mode and add a demo;
2015-03-02 when use iconv_convert from gbk to big5,automaticly alternate gbk to
gb2312;
2015-04-13 1)Maat_xx_scan will return 0 if table has no config instead of -1;
	2)use my_scandir as replacement of glibc's scandir to adapt dictator
	malloc wrap;
	3)if iconv take no effect,jump over this string;
	4)compile shortcut for performance;
	5)verify if region id is unique;
2015-04-20 fix Maat_stream_scan_string_detail and Maat_stream_scan_string wrong
	data len when open cross caching;
2015-04-21 fix add_group_to_compile bug on compatible to none-group mode;
2015-04-29 fix false hit compile rule of one more region bug;
2015-05-06 fix add_group_to_compile return add failed status bug;
2015-05-07 1)use rwlock instead of mutex in _mi_rule;
		2)fix inc postpone update bug;
2015-05-21 1)addapt rulescan ip addr host order requirement;
		2) use readdir_r in my_scandir;
		3) fix segmentfault when have no config,again;
		4) maat_json support plugin table;
2015-07-03 1)print error when Maat_summon_feather  with a dir has no valid
indexfile;
		2)check AND_EXPR's match method;
		3)remove restriction of IP table's protocol;
		4)fix invalid write in insert_set_id function;
2015-07-06 1)handle wrong expr format like "aa&&bb" and "aa&bb&";
		2)iconv_convert performance optimized;
2015-10-19 check table_type in callback register;
2015-11-09 1)add digest feature;
		2) split some code from Maat_rule.cpp to Maat_api.cpp;
2015-12-24 change plugin table update mechanism to save memory;
2016-01-20 maat_finish_cb adapt empty inc callback on a NULL scanner;
2016-01-31 trigger plugin table's callback ONLY on its table's changed;
