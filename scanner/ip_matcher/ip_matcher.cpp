#include <unistd.h>
#include <sys/syscall.h> 
#include <list>
#include <map>

#include "ip_matcher.h"
#include "rule_match.h"
#include "ipv4_match.h"
#include "ipv6_match.h"

using namespace std;

pid_t ip_matcher_gettid() 
{
	return syscall(SYS_gettid);
}

static const char *ip_matcher_module_name_str(const char *name)
{
	static __thread char module[64];
	snprintf(module,sizeof(module),"%s(%d)", name, ip_matcher_gettid());
    
	return module;
}

#define MODULE_IP_MATCHER	 ip_matcher_module_name_str("maat.ip_matcher")

int ipmatcher_VERSION_2020_05_13 = 0;

struct ip_matcher
{
	CRuleMatch *	ipv4_matcher;
	CRuleMatch *	ipv6_matcher;

    struct log_handle *logger;
#ifdef RULESCAN_DEBUG
	//for test
	double						search_time;
	int							search_cnt;
#endif
};

CRuleMatch * new_rule_matcher(enum IP_TYPE type)
{
	if(type==IPv4)
	{
		return new CIPv4Match();
	}
	else if(type==IPv6)
	{
		return new CIPv6Match();
	}
	else
	{
		return NULL;
	}
}

struct ip_matcher * ip_matcher_new(struct ip_rule * rules, size_t rule_num, 
                                   size_t * mem_use)
{
	if(rules == NULL || rule_num == 0)
	{
		return NULL;
	}

	long long mem_bytes=0;

	struct ip_matcher * matcher = new struct ip_matcher;
	mem_bytes = sizeof(struct ip_matcher);
	matcher->ipv4_matcher = NULL;
	matcher->ipv6_matcher = NULL;
    matcher->logger = logger;

	map<long long, struct ip_rule> ipv4_rules;
	map<long long, struct ip_rule> ipv6_rules;
	for(size_t i = 0; i < rule_num; i++)
	{
		long long id = rules[i].rule_id;
		if(rules[i].type == IPv4)
			ipv4_rules[id] = rules[i];
		if(rules[i].type == IPv6 )
			ipv6_rules[id] = rules[i];
	}

	//����ipv4ɨ����
	if(ipv4_rules.size() != 0)
	{	
		CRuleMatch * v4_matcher = new CIPv4Match;
		long long ret = v4_matcher->initialize(ipv4_rules);
		if(ret<0)
		{
			delete v4_matcher;
			v4_matcher=NULL;
			return NULL;
		}

		mem_bytes += ret;
		matcher->ipv4_matcher = v4_matcher;
	}

	//����ipv6ɨ����
	if(ipv6_rules.size() != 0)
	{
		CRuleMatch * v6_matcher = new CIPv6Match;
		long long ret = v6_matcher->initialize(ipv6_rules);
		if(ret<0)
		{
			delete v6_matcher;
			v6_matcher=NULL;
			return NULL;
		}

		mem_bytes += ret;
		matcher->ipv6_matcher = v6_matcher;
	}

	*mem_use = mem_bytes;

	return matcher;
}

int ip_matcher_match(struct ip_matcher* matcher, struct ip_data* data, 
                     struct scan_result* result, size_t size)
{
	if(matcher == NULL || data == NULL || result == NULL)
	{
		return -1;
	}

	CRuleMatch * tmp_matcher = NULL;

	if(data->type == IPv4)
	{
		tmp_matcher = matcher->ipv4_matcher;
	}
	if(data->type == IPv6)
	{
		tmp_matcher = matcher->ipv6_matcher;
	}

	if(tmp_matcher==NULL) 
	{
		return -1;
	}

	int ret = tmp_matcher->search_rule(data,result,size);
	if(ret<0) 
	{
		return -1;
	}

	return ret;
}

void ip_matcher_free(struct ip_matcher* matcher)
{
	if(matcher == NULL) return;

	if(matcher->ipv4_matcher != NULL)
		delete matcher->ipv4_matcher;
	if(matcher->ipv6_matcher != NULL)
		delete matcher->ipv6_matcher;

	delete matcher;
}