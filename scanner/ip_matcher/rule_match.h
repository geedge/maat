#ifndef H_RULE_MATCH_H
#define H_RULE_MATCH_H

#include "ip_matcher.h"
#include <set>
#include <map>
#include <vector>
#include <queue>
#include <stdlib.h>
using namespace std;

#ifndef __linux__
#include <windows.h>

#include <process.h>  
/*************  mutex (use CRITICAL_SECTION in windows) ***************/
#define		THREAD_MUTEX				CRITICAL_SECTION
#define		INITIALIZE_MUTEX(mutex)		InitializeCriticalSection(mutex)
#define		DESTROY_MUTEX				DeleteCriticalSection
#define		LOCK_MUTEX					EnterCriticalSection
#define		UNLOCK_MUTEX				LeaveCriticalSection
/**********************************************************************/
#else
#include <pthread.h>
#include <unistd.h>
/**************  mutex (use CRITICAL_SECTION in Linux) ***************/
#define		THREAD_MUTEX				pthread_mutex_t
#define		INITIALIZE_MUTEX(mutex)		pthread_mutex_init(mutex, NULL)		
#define		DESTROY_MUTEX				pthread_mutex_destroy
#define     LOCK_MUTEX					pthread_mutex_lock
#define		UNLOCK_MUTEX				pthread_mutex_unlock
/**********************************************************************/
#endif

class CRuleMatch
{
public:
	CRuleMatch()
	{
		
	}

	virtual ~CRuleMatch()
	{
	}

	virtual long long initialize(const map<long long, struct ip_rule>& rules)=0;

	virtual int search_rule(const struct ip_data * data, struct scan_result * presult, unsigned int size)=0;

};

#endif
