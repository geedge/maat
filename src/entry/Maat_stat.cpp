#include "Maat_rule_internal.h"
#include "field_stat.h"
enum MAAT_FS_STATUS{
	STATUS_VERSION=0,
	STATUS_TABLE_NUM,
	STATUS_OUTER_MID_NUM,
	STATUS_INNER_MID_NUM,
	STATUS_GARBAGE_QSIZE,
};

enum MAAT_FS_COLUMN
{
	COLUMN_TABLE_RULE_NUM=0,
	COLUMN_TABLE_REGEX_NUM,
	COLUMN_TABLE_STREAM_NUM,
	COLUMN_TABLE_SCAN_CNT,
	COLUMN_TABLE_SCAN_BYTES,
	COLUMN_TABLE_CPU_TIME,//microseconds
	COLUMN_TABLE_HIT_CNT
};
void maat_stat_init(struct _Maat_feather_t* feather)
{
	int value=0;
	int i=0;
	struct _Maat_table_info_t* p_table=NULL;

	feather->stat_handle=FS_create_handle();
	FS_set_para(feather->stat_handle, OUTPUT_DEVICE, feather->stat_file, strlen(feather->stat_file)+1);
	value=1;
	FS_set_para(feather->stat_handle, PRINT_MODE, &value, sizeof(value));
	value=0;
	FS_set_para(feather->stat_handle, CREATE_THREAD, &value, sizeof(value));
	
	feather->fs_status_id[STATUS_VERSION]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"version");
	feather->fs_status_id[STATUS_TABLE_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"table_num");
	feather->fs_status_id[STATUS_OUTER_MID_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"outer_mid");
	feather->fs_status_id[STATUS_INNER_MID_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"inner_mid");
	feather->fs_status_id[STATUS_GARBAGE_QSIZE]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"garbage_num");

	feather->fs_column_id[COLUMN_TABLE_RULE_NUM]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,"rule");
	feather->fs_column_id[COLUMN_TABLE_REGEX_NUM]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,"regex");
	feather->fs_column_id[COLUMN_TABLE_STREAM_NUM]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,"stream");
	feather->fs_column_id[COLUMN_TABLE_SCAN_CNT]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"scan_cps");
	feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"IN_Bps");
	if(feather->perf_on==1)
	{
		feather->fs_column_id[COLUMN_TABLE_CPU_TIME]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"cpu_us");
		value=feather->fs_column_id[COLUMN_TABLE_CPU_TIME];
		FS_set_para(feather->stat_handle, ID_INVISBLE, &value, sizeof(value));
		FS_register_ratio(feather->stat_handle,
						feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES], 
						feather->fs_column_id[COLUMN_TABLE_CPU_TIME], 
						FS_STYLE_COLUMN,
						FS_CALC_SPEED,
						"PROC_Bps");
	}
	feather->fs_column_id[COLUMN_TABLE_HIT_CNT]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"hit_cnt");
	value=feather->fs_column_id[COLUMN_TABLE_HIT_CNT];
	FS_set_para(feather->stat_handle, ID_INVISBLE, &value, sizeof(value));
	FS_register_ratio(feather->stat_handle,
					feather->fs_column_id[COLUMN_TABLE_HIT_CNT], 
					feather->fs_column_id[COLUMN_TABLE_SCAN_CNT], 
					FS_STYLE_COLUMN,
					FS_CALC_SPEED,
					"hit_rate");
	feather->total_stat_id=FS_register(feather->stat_handle, FS_STYLE_LINE, FS_CALC_CURRENT,"Sum");
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		p_table=feather->p_table_info[i];
		if(p_table==NULL||p_table->table_type==TABLE_TYPE_PLUGIN
						||p_table->table_type==TABLE_TYPE_GROUP
						||p_table->table_type==TABLE_TYPE_COMPILE)
		{
			continue;
		}
		p_table->stat_line_id=FS_register(feather->stat_handle, FS_STYLE_LINE, FS_CALC_CURRENT,p_table->table_name);	
	}
	FS_start(feather->stat_handle);
	return;
}
void maat_stat_table(struct _Maat_table_info_t* p_table,int scan_len,struct timeval* start, struct timeval* end)
{
	p_table->scan_cnt++;
	p_table->input_bytes+=scan_len;
	p_table->scan_cpu_time+=(end->tv_sec-start->tv_sec)*1000000+end->tv_usec-start->tv_usec;
	return;
}
void maat_stat_output(struct _Maat_feather_t* feather)
{
	long value=0;
	long long total_cfg_num=0, total_input_bytes=0, total_regex_num=0;
	long long total_scan_cnt=0, total_cpu_time=0,total_stream_cnt=0;
	int i=0;
	struct _Maat_table_info_t* p_table=NULL;

	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_VERSION], 0,FS_OP_SET,feather->maat_version);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_TABLE_NUM], 0,FS_OP_SET,feather->table_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_OUTER_MID_NUM], 0,FS_OP_SET,feather->outer_mid_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_INNER_MID_NUM], 0,FS_OP_SET,feather->inner_mid_cnt);

	value=MESA_lqueue_get_count(feather->garbage_q);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_GARBAGE_QSIZE], 0,FS_OP_SET,value);

	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		p_table=feather->p_table_info[i];
		if(p_table==NULL||p_table->table_type==TABLE_TYPE_PLUGIN
						||p_table->table_type==TABLE_TYPE_GROUP
						||p_table->table_type==TABLE_TYPE_COMPILE)
		{
			continue;
		}
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_RULE_NUM],
					FS_OP_SET,
					p_table->cfg_num);
		total_cfg_num+=p_table->cfg_num;
		
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_REGEX_NUM],
					FS_OP_SET,
					p_table->regex_rule_cnt);
		total_regex_num+= p_table->regex_rule_cnt;

		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_STREAM_NUM],
					FS_OP_SET,
					p_table->stream_num);
		total_stream_cnt+= p_table->stream_num;
		
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_SCAN_CNT],
					FS_OP_ADD,
					p_table->scan_cnt);
		total_scan_cnt+=p_table->scan_cnt;
		p_table->scan_cnt=0;
		
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES],
					FS_OP_ADD,
					p_table->input_bytes);
		total_input_bytes+=p_table->input_bytes;
		p_table->input_bytes=0;
		if(feather->perf_on==1)
		{
			FS_operate(feather->stat_handle,
						p_table->stat_line_id,
						feather->fs_column_id[COLUMN_TABLE_CPU_TIME],
						FS_OP_ADD,
						p_table->scan_cpu_time);
			total_cpu_time+=p_table->scan_cpu_time;
			p_table->scan_cpu_time=0;
		}
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_HIT_CNT],
					FS_OP_ADD,
					p_table->hit_cnt);
		//total hit count stat in region_compile
		p_table->hit_cnt=0;	
	}
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_RULE_NUM], 
				FS_OP_SET,
				total_cfg_num);
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_REGEX_NUM], 
				FS_OP_SET,
				total_regex_num);
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_STREAM_NUM], 
				FS_OP_SET,
				total_stream_cnt);
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_SCAN_CNT], 
				FS_OP_ADD,
				total_scan_cnt);
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES], 
				FS_OP_ADD,
				total_input_bytes);
	if(feather->perf_on==1)
	{
		FS_operate(feather->stat_handle,
					feather->total_stat_id, 
					feather->fs_column_id[COLUMN_TABLE_CPU_TIME], 
					FS_OP_ADD,
					total_cpu_time);
	}
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_HIT_CNT], 
				FS_OP_ADD,
				feather->hit_cnt);
	feather->hit_cnt=0;
	FS_passive_output(feather->stat_handle);
	return;
}

