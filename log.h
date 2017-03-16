#ifndef __LOG_H_
#define __LOG_H_

#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <stdlib.h>

/*for log level*/
extern int g_nLogLevel;	//日志级别
extern int g_nReqLogLevel;	
extern int g_nRespLogLevel;
extern int g_nForeground;	//日志输出方式

#define	LOG_SYSTEM(fmtx...) \
	({ \
		int __ret; \
		char __temp[1024] = { '\0', }; \
		snprintf(__temp, sizeof(__temp), fmtx); \
		__ret = system(__temp); \
		__ret; \
	})

/*for func show_log_file_record in log.c*/
#define LOG_KEYWORD_POSITION	23
/* for log dir */
#define LOG_BASE_FILE_PATH			"./log/"
#define LOG_FILE_NAME						"syslog.log"

#define	DEF_SYS_TIME_LEN	24
#define	DEF_THE_TIME_OUT	2
#define	DEF_LOG_BUFF_LEN	(1*1024*1024)

#define	MIN_LOG_FILE_IDX	5
#define	MAX_LOG_FILE_IDX	200
#define	DEF_LOG_FILE_IDX	MAX_LOG_FILE_IDX

#define	MIN_LOG_FILE_SIZE	10
#define	MAX_LOG_FILE_SIZE	100
#define	DEF_LOG_FILE_SIZE	MAX_LOG_FILE_SIZE

#define	MIN_BUFFER_SIZE			1024	
#define	LOGBUFFER_CHAIN_SIZE	sizeof(struct logbuffer_chain)
#define	LOGBUFFER_CHAIN_EXTRA(t, c) (t *)((struct logbuffer_chain *)(c) + 1)

#define	LOGBUFFER_LOCK_INIT(a)	do {pthread_mutex_init(&(a), NULL);} while (0)
#define	LOGBUFFER_LOCK_DESTROY(a)	do {pthread_mutex_destroy(&(a));} while (0)	
#define	LOGBUFFER_LOCK_ENTER(a)	do {pthread_mutex_lock(&(a));} while (0)
#define	LOGBUFFER_LOCK_LEAVE(a)	do {pthread_mutex_unlock(&(a));} while (0)	

enum {
	SYS_LOG_ALM,
	SYS_LOG_ERR,
	SYS_LOG_INFO,
	SYS_LOG_DBG,
	SYS_LOG_ALL,
};

struct logbuffer_chain {
	size_t buffer_len;
	size_t off;
	size_t next_idx;
	char* file;	
	unsigned char* buffer;
	pthread_mutex_t lock;
};

enum {
	LOG_MODULE=0,
	LOG_MODULE_REQUEST=1,
	LOG_MODULE_RESPONSE=2,	
	LOG_MODULE_MAX
};

extern void init_log();
extern void register_log(int md, const char* filepath);
extern void destroy_log(int md);
extern void write_log(int md, const char* fmt, ...);
extern int show_log_file_record(char **outbuf, const char * fname, const char * keywords, 
		const char * trange, size_t page, size_t pageline);
extern void set_log_max_idx(int idx);
extern void set_log_max_size(int size);

/* for log */
#define log_alarm(mid, fmt, arg...) do \
	{ \
		if (g_nLogLevel>=SYS_LOG_ALM)\
		{\
			if (g_nForeground)\
			{\
				printf("[alarm] %u|  %s| "fmt, mid, __FILE__, ##arg);\
			}\
			else\
			{\
				write_log(LOG_MODULE, "[alarm] [pid:%u] %s|"fmt, mid, __FILE__, ##arg);\
			}\
		}\
	} while(0)
	
#define log_error(mid, fmt, arg...) do \
	{ \
		if (g_nLogLevel>=SYS_LOG_ERR)\
		{\
			if (g_nForeground)\
			{\
				printf("[error] %u|  %s| "fmt,mid,__FILE__,##arg);\
			}\
			else\
			{\
				write_log(LOG_MODULE, "[error] [pid:%u] %s|"fmt, mid, __FILE__, ##arg);\
			}\
		}\
	} while(0)

#define log_info(mid, fmt, arg...) do \
	{ \
		if (g_nLogLevel>=SYS_LOG_INFO)\
		{\
			if (g_nForeground)\
			{\
				printf("[info]  %u|  %s| "fmt,mid,__FILE__,##arg);\
			}\
			else\
			{\
				write_log(LOG_MODULE, "[info]  [pid:%u] %s|"fmt, mid, __FILE__, ##arg);\
			}\
		}\
	} while(0)

#define log_debug(mid, fmt, arg...) do \
	{ \
		if (g_nLogLevel>=SYS_LOG_DBG)\
		{\
			if (g_nForeground)\
			{\
				printf("[debug] %u|  %s| "fmt,mid,__FILE__, ##arg);\
			}\
			else\
			{\
				write_log(LOG_MODULE, "[debug] [pid:%u] %s|"fmt, mid, __FILE__, ##arg);\
			}\
		}\
	} while(0)
	
#endif
