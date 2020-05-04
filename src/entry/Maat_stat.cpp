#include "Maat_rule_internal.h"
#include "Maat_table.h"
#include "alignment_int64.h"
#include <time.h>
#include <MESA/field_stat.h>
enum MAAT_FS_STATUS{
	STATUS_VERSION=0,
	STATUS_THRED_NUM,
	STATUS_TABLE_NUM,
	STATUS_PLUGIN_CACHE_NUM,
	STATUS_PLUGIN_ACC_NUM,
	STATUS_GROUP_REF_NUM,
	STATUS_GROUP_REF_NOT_NUM,
	STATUS_COMPILE_RULE_NUM,
	STATUS_POSTPONE_QSIZE,
	STATUS_OUTER_MID_NUM,
	STATUS_INNER_MID_NUM,
	STATUS_GARBAGE_QSIZE,
	STATUS_TOTAL_SCAN_LEN,
	STATUS_TOTAL_SCAN_CNT,
	STATUS_UPDATE_ERR_CNT,
	STATUS_ICONV_ERR_CNT,
	STATUS_SCAN_ERR_CNT,
	STATUS_ZOMBIE_RS_STREAM,
	STATUS_NOT_GROUP_HIT,
	STATUS_CMD_NUM,
	STATUS_CMD_Q_SIZE,
	STATUS_CMD_LINE_NUM
};

enum MAAT_FS_COLUMN
{
	COLUMN_TABLE_RULE_NUM=0,
	COLUMN_TABLE_REGEX_NUM,
	COLUMN_TABLE_STREAM_NUM,
	COLUMN_TABLE_SCAN_CNT,
	COLUMN_TABLE_SCAN_BYTES,
	COLUMN_TABLE_CPU_TIME,//microseconds
	COLUMN_TABLE_HIT_CNT,
};
#define	MAX_CONJ_NAME_LEN	22
void maat_stat_init(struct _Maat_feather_t* feather)
{
	int value=0;
	int i=0,j=0,offset=0;
	struct Maat_table_schema* p_table=NULL;
	char conj_table_name[(MAX_TABLE_NAME_LEN+1)*MAX_CONJUNCTION_TABLE_NUM]={0};

	feather->stat_handle=FS_create_handle();
	FS_set_para(feather->stat_handle, OUTPUT_DEVICE, feather->stat_file, strlen(feather->stat_file)+1);
	value=1;
	FS_set_para(feather->stat_handle, PRINT_MODE, &value, sizeof(value));
	value=0;
	FS_set_para(feather->stat_handle, CREATE_THREAD, &value, sizeof(value));

	FS_set_para(feather->stat_handle, APP_NAME, feather->instance_name, strlen(feather->instance_name)+1);
	
	feather->fs_status_id[STATUS_VERSION]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"version");
	feather->fs_status_id[STATUS_THRED_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"threads");
	feather->fs_status_id[STATUS_TABLE_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"tables");

	feather->fs_status_id[STATUS_PLUGIN_CACHE_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"plug_cached");
	feather->fs_status_id[STATUS_PLUGIN_ACC_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"plug_acc");

	feather->fs_status_id[STATUS_GROUP_REF_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"group");
	feather->fs_status_id[STATUS_GROUP_REF_NOT_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"not_grp");
	feather->fs_status_id[STATUS_COMPILE_RULE_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"compile");

	feather->fs_status_id[STATUS_POSTPONE_QSIZE]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"postponed");
	feather->fs_status_id[STATUS_GARBAGE_QSIZE]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"garbage_num");	

	feather->fs_status_id[STATUS_OUTER_MID_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"outer_mid");
	feather->fs_status_id[STATUS_INNER_MID_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"inner_mid");
	feather->fs_status_id[STATUS_ZOMBIE_RS_STREAM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"z_stream");

	feather->fs_status_id[STATUS_NOT_GROUP_HIT]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"nt_grp_hit");

	feather->fs_status_id[STATUS_TOTAL_SCAN_LEN]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"scan_bytes");
	feather->fs_status_id[STATUS_TOTAL_SCAN_CNT]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"scan_times");
	feather->fs_status_id[STATUS_UPDATE_ERR_CNT]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"update_err");
	feather->fs_status_id[STATUS_ICONV_ERR_CNT]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"iconv_err");
	feather->fs_status_id[STATUS_SCAN_ERR_CNT]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"scan_error");
	feather->fs_status_id[STATUS_CMD_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"cmd_commit");
	feather->fs_status_id[STATUS_CMD_Q_SIZE]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_CURRENT,"cmd_in_q");
	feather->fs_status_id[STATUS_CMD_LINE_NUM]=FS_register(feather->stat_handle, FS_STYLE_STATUS, FS_CALC_SPEED,"line_cmd/s");

	feather->fs_column_id[COLUMN_TABLE_RULE_NUM]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,"rule");
	feather->fs_column_id[COLUMN_TABLE_REGEX_NUM]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,"reg/v6");
	feather->fs_column_id[COLUMN_TABLE_STREAM_NUM]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,"stream");
	feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"IN_Bps");
	if(feather->perf_on==1)
	{
		feather->fs_column_id[COLUMN_TABLE_CPU_TIME]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"cpu_us");
		value=feather->fs_column_id[COLUMN_TABLE_CPU_TIME];
		FS_set_para(feather->stat_handle, ID_INVISBLE, &value, sizeof(value));
		FS_register_ratio(feather->stat_handle,
						feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES], 
						feather->fs_column_id[COLUMN_TABLE_CPU_TIME], 
						1000000,		//microsecond to second
						FS_STYLE_COLUMN,
						FS_CALC_SPEED,
						"PROC_Bps");
	}
	feather->fs_column_id[COLUMN_TABLE_SCAN_CNT]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"IN_Tps");
	if(feather->perf_on==1)
	{	
		FS_register_ratio(feather->stat_handle,
						feather->fs_column_id[COLUMN_TABLE_SCAN_CNT], 
						feather->fs_column_id[COLUMN_TABLE_CPU_TIME], 
						1000000,		//microsecond to second
						FS_STYLE_COLUMN,
						FS_CALC_SPEED,
						"PROC_Tps");
	}
	feather->fs_column_id[COLUMN_TABLE_HIT_CNT]=FS_register(feather->stat_handle, FS_STYLE_COLUMN, FS_CALC_SPEED,"hit_cnt");
	value=feather->fs_column_id[COLUMN_TABLE_HIT_CNT];
	FS_set_para(feather->stat_handle, ID_INVISBLE, &value, sizeof(value));
	FS_register_ratio(feather->stat_handle,
					feather->fs_column_id[COLUMN_TABLE_HIT_CNT], 
					feather->fs_column_id[COLUMN_TABLE_SCAN_CNT], 
					1,
					FS_STYLE_COLUMN,
					FS_CALC_SPEED,
					"hit_rate");
	feather->total_stat_id=FS_register(feather->stat_handle, FS_STYLE_LINE, FS_CALC_CURRENT, "Sum");
	size_t max_table_num=Maat_table_manager_get_size(feather->table_mgr);
	for(i=0; i<(int)max_table_num; i++)
	{
		p_table=Maat_table_get_by_id_raw(feather->table_mgr, i);
		if(p_table==NULL||p_table->table_type==TABLE_TYPE_PLUGIN
						||p_table->table_type==TABLE_TYPE_GROUP
						||p_table->table_type==TABLE_TYPE_COMPILE)
		{
			continue;
		}
		offset=0;
		for(j=0;j<p_table->conj_cnt;j++)
		{
			offset+=snprintf(conj_table_name+offset,sizeof(conj_table_name)-offset
							,"%s/",p_table->table_name[j]);
		}
		conj_table_name[offset-1]='\0';//delete the last slash
		if(strlen(conj_table_name)>MAX_CONJ_NAME_LEN)
		{
			conj_table_name[MAX_CONJ_NAME_LEN]='\0';
		}
		p_table->stat_line_id=FS_register(feather->stat_handle
										, FS_STYLE_LINE, FS_CALC_CURRENT
										,conj_table_name);
	}
	FS_start(feather->stat_handle);
	return;
}
void maat_stat_table(struct Maat_table_runtime* p,int scan_len,struct timespec* start, struct timespec* end,int thread_num)
{
	alignment_int64_array_add(p->scan_cnt,thread_num,1);
	alignment_int64_array_add(p->input_bytes,thread_num,scan_len);
	if(start!=NULL&&end!=NULL)
	{
		alignment_int64_array_add(p->scan_cpu_time,thread_num,(end->tv_sec-start->tv_sec)*1000000000+end->tv_nsec-start->tv_nsec);
	}
	return;
}
void maat_stat_output(struct _Maat_feather_t* feather)
{
	long value=0;
	long long total_cfg_num=0, table_regex_ipv6_num=0, total_input_bytes=0, total_regex_num=0,total_hit_cnt=0;
	long long total_scan_cnt=0, total_cpu_time=0,total_stream_cnt=0,active_thread_num=0;
	long long table_stream_num=0,table_scan_cnt=0,table_input_bytes=0,table_scan_cpu_time=0,table_hit_cnt=0;
	long long outer_mid_cnt=0,inner_mid_cnt=0;
	long long not_grp_hit_cnt=0;
	long long total_update_error=0,total_iconv_error=0;
	long long compile_rule_num=0, group_rule_num=0, not_group_rule_num=0, plugin_cache_num=0, plugin_acc_num=0;
	int i=0;
	time_t now;
	struct Maat_table_schema* p_table=NULL;
	struct Maat_table_runtime* table_rt=NULL;
	time(&now);
	if(feather->scanner==NULL)
	{
		return;
	}
	active_thread_num=alignment_int64_array_cnt(feather->thread_call_cnt, feather->scan_thread_num);
	outer_mid_cnt=alignment_int64_array_sum(feather->outer_mid_cnt,feather->scan_thread_num);
	inner_mid_cnt=alignment_int64_array_sum(feather->inner_mid_cnt,feather->scan_thread_num);
	not_grp_hit_cnt=alignment_int64_array_sum(feather->not_grp_hit_cnt,feather->scan_thread_num);

	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_VERSION], 0,FS_OP_SET,feather->maat_version);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_THRED_NUM], 0,FS_OP_SET,active_thread_num);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_TABLE_NUM], 0,FS_OP_SET,Maat_table_manager_get_count(feather->table_mgr));

	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_OUTER_MID_NUM], 0,FS_OP_SET,outer_mid_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_INNER_MID_NUM], 0,FS_OP_SET,inner_mid_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_NOT_GROUP_HIT], 0,FS_OP_SET,not_grp_hit_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_CMD_NUM], 0,FS_OP_SET,feather->cmd_acc_num);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_CMD_Q_SIZE], 0,FS_OP_SET,feather->cmd_q_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_CMD_LINE_NUM], 0,FS_OP_SET,feather->line_cmd_acc_num);

	value=MESA_lqueue_get_count(feather->garbage_q);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_GARBAGE_QSIZE], 0,FS_OP_SET,value);
	feather->update_err_cnt=0;
	feather->iconv_err_cnt=0;
	size_t max_table_num=Maat_table_manager_get_size(feather->table_mgr);
	for(i=0; i<(int)max_table_num; i++)
	{
		table_stream_num=0;
		table_scan_cnt=0;
		table_input_bytes=0;
		table_scan_cpu_time=0;
		table_hit_cnt=0;
		table_regex_ipv6_num=0;
		
		p_table=Maat_table_get_by_id_raw(feather->table_mgr, i);
		if(p_table==NULL)
		{
			continue;
		}
		table_rt=Maat_table_runtime_get(feather->scanner->table_rt_mgr, i);
		switch(p_table->table_type)
		{
			case TABLE_TYPE_PLUGIN:
				plugin_cache_num+=table_rt->plugin.ex_data_rt->cache_row_num;
				plugin_acc_num+=table_rt->plugin.acc_line_num;
				break;
			case TABLE_TYPE_GROUP:
				group_rule_num+=table_rt->origin_rule_num;
				not_group_rule_num+=table_rt->group.not_flag_group;
				break;
			case TABLE_TYPE_COMPILE:
				compile_rule_num+=table_rt->origin_rule_num;
				break;
			case TABLE_TYPE_EXPR:
			case TABLE_TYPE_EXPR_PLUS:
				table_regex_ipv6_num=table_rt->expr.regex_rule_cnt;
				total_iconv_error=p_table->expr.iconv_err_cnt;
				break;
			case TABLE_TYPE_IP:
			case TABLE_TYPE_IP_PLUS:
				table_regex_ipv6_num=table_rt->ip.ipv6_rule_cnt;
				break;
			default:
				break;
		}
		if(p_table->table_type==TABLE_TYPE_PLUGIN||
			p_table->table_type==TABLE_TYPE_GROUP||
			p_table->table_type==TABLE_TYPE_COMPILE)
		{
			continue;
		}
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_RULE_NUM],
					FS_OP_SET,
					table_rt->origin_rule_num);
		total_cfg_num+=table_rt->origin_rule_num;
		
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_REGEX_NUM],
					FS_OP_SET,
					table_regex_ipv6_num);
		total_regex_num+=table_regex_ipv6_num;

		table_stream_num=alignment_int64_array_sum(table_rt->stream_num,feather->scan_thread_num);
		alignment_int64_array_reset(table_rt->stream_num,feather->scan_thread_num);
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_STREAM_NUM],
					FS_OP_ADD,
					table_stream_num);
		total_stream_cnt+= table_stream_num;
		

		table_scan_cnt=alignment_int64_array_sum(table_rt->scan_cnt,feather->scan_thread_num);
		alignment_int64_array_reset(table_rt->scan_cnt,feather->scan_thread_num);
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_SCAN_CNT],
					FS_OP_ADD,
					table_scan_cnt);
		total_scan_cnt+=table_scan_cnt;

		table_input_bytes=alignment_int64_array_sum(table_rt->input_bytes,feather->scan_thread_num);
		alignment_int64_array_reset(table_rt->input_bytes,feather->scan_thread_num);
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_SCAN_BYTES],
					FS_OP_ADD,
					table_input_bytes);
		total_input_bytes+=table_input_bytes;
		if(feather->perf_on==1)
		{
			table_scan_cpu_time=alignment_int64_array_sum(table_rt->scan_cpu_time,feather->scan_thread_num);
			alignment_int64_array_reset(table_rt->scan_cpu_time,feather->scan_thread_num);
			table_scan_cpu_time/=1000;
			FS_operate(feather->stat_handle,
						p_table->stat_line_id,
						feather->fs_column_id[COLUMN_TABLE_CPU_TIME],
						FS_OP_ADD,
						table_scan_cpu_time);
			total_cpu_time+=table_scan_cpu_time;
		}
		
		table_hit_cnt=alignment_int64_array_sum(table_rt->hit_cnt,feather->scan_thread_num);
		alignment_int64_array_reset(table_rt->hit_cnt,feather->scan_thread_num);
		FS_operate(feather->stat_handle,
					p_table->stat_line_id,
					feather->fs_column_id[COLUMN_TABLE_HIT_CNT],
					FS_OP_ADD,
					table_hit_cnt);
		total_update_error+=p_table->udpate_err_cnt;
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
				FS_OP_ADD,
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
	total_hit_cnt=alignment_int64_array_sum(feather->hit_cnt, feather->scan_thread_num);
	alignment_int64_array_reset(feather->hit_cnt,feather->scan_thread_num);
	FS_operate(feather->stat_handle,
				feather->total_stat_id, 
				feather->fs_column_id[COLUMN_TABLE_HIT_CNT], 
				FS_OP_ADD,
				total_hit_cnt);
	feather->total_scan_bytes+=total_input_bytes;
	feather->total_scan_cnt+=total_scan_cnt;
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_TOTAL_SCAN_LEN], 0,FS_OP_SET,feather->total_scan_bytes);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_TOTAL_SCAN_CNT], 0,FS_OP_SET,feather->total_scan_cnt);
	feather->update_err_cnt=total_update_error;
	feather->iconv_err_cnt=total_iconv_error;
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_UPDATE_ERR_CNT], 0,FS_OP_SET,feather->update_err_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_ICONV_ERR_CNT], 0,FS_OP_SET,feather->iconv_err_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_SCAN_ERR_CNT], 0,FS_OP_SET,feather->scan_err_cnt);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_ZOMBIE_RS_STREAM], 0,FS_OP_SET,feather->zombie_rs_stream);

	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_PLUGIN_CACHE_NUM], 0,FS_OP_SET,plugin_cache_num);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_PLUGIN_ACC_NUM], 0,FS_OP_SET,plugin_acc_num);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_GROUP_REF_NUM], 0,FS_OP_SET,group_rule_num);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_GROUP_REF_NOT_NUM], 0,FS_OP_SET,not_group_rule_num);
	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_COMPILE_RULE_NUM], 0,FS_OP_SET,compile_rule_num);

	FS_operate(feather->stat_handle, feather->fs_status_id[STATUS_POSTPONE_QSIZE], 0,FS_OP_SET,feather->postpone_q_size);

	FS_passive_output(feather->stat_handle);
	return;
}

