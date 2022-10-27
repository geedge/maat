
struct ip_runtime
{
	EX_data_rt *effect_items;
	struct ip_matcher *matcher;
};
struct table_runtime
{
	struct hash_table item_hash;
	enum table_type type;
	union
	{
		struct ip_runtime *ip_rt;
	};
};
