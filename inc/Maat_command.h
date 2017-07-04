#ifndef H_MAAT_COMMAND_H_INCLUDE
#define H_MAAT_COMMAND_H_INCLUDE
#ifndef __cplusplus
#error("This file should be compiled with C++ compiler")
#endif
#include "Maat_rule.h"
enum MAAT_OPERATION
{
	MAAT_OP_DEL=0,
	MAAT_OP_ADD
};
enum MAAT_REGION_TYPE
{
	REGION_EXPR,
	REGION_IP,
	REGION_INTERVAL,
	REGION_DIGEST,
	REGION_SIMILARITY
};
enum MAAT_EXPR_TYPE
{	
	EXPR_TYPE_STRING=0,
	EXPR_TYPE_AND,
	EXPR_TYPE_REGEX,
	EXPR_TYPE_OFFSET
};
enum MAAT_MATCH_METHOD
{	
	MATCH_METHOD_SUB=0,
	MATCH_METHOD_RIGHT,
	MATCH_METHOD_LEFT,
	MATCH_METHOD_COMPLETE
};

enum MAAT_CASE_TYPE
{
	UNCASE_PLAIN=0,
	CASE_HEXBIN,
	CASE_PLAIN
};
enum MAAT_ADDR_TYPE
{
	ADDR_TYPE_IPv4=4,
	ADDR_TYPE_IPv6=6
};
enum MAAT_ADDR_DIRECTION
{
	ADDR_DIR_DOUBLE=0,
	ADDR_DIR_SINGLE=1
};
struct Maat_rgn_str_t
{
	const char *keywords;
	const char *district;// optional for expr_plus, otherwise set to NULL.
	enum MAAT_EXPR_TYPE expr_type;
	enum MAAT_MATCH_METHOD match_method;
	enum MAAT_CASE_TYPE hex_bin;
};
struct Maat_rgn_addr_t
{
	enum MAAT_ADDR_TYPE addr_type;
	const char* src_ip;
	const char* mask_src_ip;
	const char* dst_ip;
	const char* mask_dst_ip;
	unsigned short src_port;
	unsigned short mask_src_port;
	unsigned short dst_port;
	unsigned short mask_dst_port;
	unsigned short protocol;
	enum MAAT_ADDR_DIRECTION direction;
};
struct Maat_rgn_intv_t
{
	unsigned int low_boundary;
	unsigned int up_boundary;
};
struct Maat_rgn_digest_t
{
	unsigned long long orgin_len;
	const char* digest_string;
	short confidence_degree;
};
struct Maat_rgn_sim_t
{
	char* target_string;
	short confidence_degree;
};
struct Maat_region_t
{
	const char* table_name;
	int region_id;	//Any, maat will assigned one.
	enum MAAT_REGION_TYPE region_type;
	union
	{
		struct Maat_rgn_str_t expr_rule;
		struct Maat_rgn_addr_t ip_rule;
		struct Maat_rgn_intv_t interval_rule;
		struct Maat_rgn_digest_t digest_rule;
		struct Maat_rgn_sim_t similarity_rule;
	};
};
struct Maat_group_t
{
	int region_num;
	int group_id;	//Any, maat will assigned one.
	char* group_name;//optional, for group reuse.
	struct Maat_region_t *regions;	
};
struct Maat_command_t
{
	struct Maat_rule_t compile;// for MAAT_OP_DEL, only compile.config_id is necessary.
	int group_num;				// for MAAT_OP_DEL, Any.
	struct Maat_group_t* groups;// for MAAT_OP_DEL, SET to NULL.
};
struct Maat_command_t* Maat_create_comand(const struct Maat_rule_t* rule, int group_num);
void Maat_cmd_add_region(struct Maat_command_t* cmd,int which_group,const struct Maat_region_t* region);
void Maat_free_command(struct Maat_command_t* cmd);
int Maat_format_command(struct Maat_command_t* cmd, char* buffer, int size);

// The command functions are NOT thread safe.
int Maat_command(Maat_feather_t feather,struct Maat_command_t* cmd,enum MAAT_OPERATION op);

//pipeline model
int Maat_append_command(Maat_feather_t feather,struct Maat_command_t* cmd,enum MAAT_OPERATION op);
int Maat_commit_command(Maat_feather_t feather);
#endif

