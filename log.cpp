// system header files
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/shm.h>

// user-defined header files
#include "log.h"

unsigned int g_max_idx = DEF_LOG_FILE_IDX;
static long g_max_size = DEF_LOG_FILE_SIZE * 1024 * 1024;
static struct logbuffer_chain* g_logbuffer_chain[LOG_MODULE_MAX]={NULL,NULL,NULL};

static struct logbuffer_chain* logbuffer_chain_new(size_t size)
{
	struct logbuffer_chain *chain=NULL;
	size_t to_alloc;
	size += LOGBUFFER_CHAIN_SIZE;
	to_alloc = MIN_BUFFER_SIZE;
	while (to_alloc < size)
		to_alloc <<= 1;
	if ((chain = (struct logbuffer_chain *)malloc(to_alloc)) == NULL)
		return (NULL);
	memset(chain, 0, LOGBUFFER_CHAIN_SIZE);
	chain->buffer_len = to_alloc - LOGBUFFER_CHAIN_SIZE;
	chain->buffer = LOGBUFFER_CHAIN_EXTRA(u_char, chain);
	return (chain);
}

static void logbuffer_chain_free(struct logbuffer_chain* chain)
{
	if (chain) free(chain);
}

static inline int gettime(char* _buffer, size_t _buffer_len)
{
	time_t _now;
	struct tm *_p;
	
	_now = time(NULL);
	_p = localtime(&_now);
	return strftime(_buffer, _buffer_len, "[%Y-%m-%d %H:%M:%S]", _p);
}

//===============================================================
//do_rotate_file
//日志回滚
//===============================================================
static void do_rotate_file(struct logbuffer_chain* chain)
{
	char szFileName[256] = {'\0'};
	if ( ! chain) return;
	if (chain->next_idx > g_max_idx || chain->next_idx < 1) chain->next_idx = 1;
	snprintf(szFileName, sizeof(szFileName)-1, "%s.%d", chain->file, (int)chain->next_idx++);		
	LOG_SYSTEM("mv -f %s %s", chain->file, szFileName);
}

static void do_write_log(struct logbuffer_chain* chain)
{
	int wlen = 0;
	FILE *fp=NULL;
	struct stat st;
	
	if ( ! chain) return;
	
	/* this place we need ignore sighup when syslog rotate */
	signal(SIGHUP, SIG_IGN);
	
	LOGBUFFER_LOCK_ENTER(chain->lock);
	if ( ! stat(chain->file, &st) && (st.st_size >= g_max_size))
		do_rotate_file(chain); 
	
	fprintf(stdout, "[do_write_log] chain->off %ld\n", chain->off);
	if (chain->off <= 0) {
		chain->off = 0;
		LOGBUFFER_LOCK_LEAVE(chain->lock);
		return;
	}
	fp = fopen(chain->file, "a+");
	if ( ! fp) {
		fprintf(stderr, "[do_write_log] open %s failed, errno:[%d]\n", chain->file, errno);
		LOGBUFFER_LOCK_LEAVE(chain->lock);
		return;
	}
	
	wlen = fwrite(chain->buffer, 1, chain->off, fp);
	fprintf(stdout, "[do_write_log] write %s\n", chain->buffer);
	if (wlen < 0) {
		fprintf(stderr, "[do_write_log] fwrite %s failed, errno:[%d]\n", chain->file, errno);
		if (fp) fclose(fp);
		LOGBUFFER_LOCK_LEAVE(chain->lock);
		return;
	}
	
	/* reset memory */
	fflush(fp);
	chain->off -= wlen;
		
	if (fp) fclose(fp);
	LOGBUFFER_LOCK_LEAVE(chain->lock);
}

//===============================================================
//pthread_log
//日志处理线程
//===============================================================
static void* pthread_log(void* param)
{
	int i = 0;
	int wlen = 0;
	FILE *fp=NULL;
	struct stat st;
	struct logbuffer_chain* chain=NULL;
	/*忽略类型为SIGHUP的信号*/
	signal(SIGHUP, SIG_IGN);
	/* 进程重命名 */
	prctl(PR_SET_NAME, (long)"log", 0, 0, 0);
	while (1) {
		for (i=0; i < LOG_MODULE_MAX; ++i) {
			/* 等待register_log日志模块触发 */
			if (g_logbuffer_chain[i]){
				chain = g_logbuffer_chain[i];
				LOGBUFFER_LOCK_ENTER(chain->lock);
				if ( ! stat(chain->file, &st) && (st.st_size >= g_max_size))
					do_rotate_file(chain); 
				
				/* 等待chain->off触发，循环写日志chain->buffer */
				if (chain->off <= 0) {
					chain->off = 0;
					LOGBUFFER_LOCK_LEAVE(chain->lock);
					continue;
				}
				fp = fopen(chain->file, "a+");
				if ( ! fp) {
					fprintf(stderr, "[pthread_log] open %s failed, errno:[%d]\n", chain->file, errno);
					LOGBUFFER_LOCK_LEAVE(chain->lock);
					continue;
				}
				wlen = fwrite(chain->buffer, 1, chain->off, fp);
				if (wlen < 0) {
					fprintf(stderr, "[do_write_log] fwrite %s failed, errno:[%d]\n", chain->file, errno);
					if (fp){
						fclose(fp);
						fp=NULL;
					}
					LOGBUFFER_LOCK_LEAVE(chain->lock);
					continue;
				}
				
				/* reset memory */
				if (fflush(fp)!=0)
					fprintf(stderr, "[do_write_log] fflush %s failed, errno:[%d]\n", chain->file, errno);
				chain->off -= wlen;
				if (fp) {
						fclose(fp);
						fp=NULL;
				}
				LOGBUFFER_LOCK_LEAVE(chain->lock);
			}
		}
		sleep(DEF_THE_TIME_OUT);	
	}
	return NULL;
}

//===============================================================
//init_log
//初始化日志：创建日志模块和日志处理线程
//===============================================================
void init_log(void)
{
	int i=0;
	pthread_t tid;
		
	for (; i < LOG_MODULE_MAX; ++i) 
		g_logbuffer_chain[i] = NULL;	

	fprintf(stdout, "create thread to write log....\n");
	
	/* create a new thread to handle write log */
	pthread_create(&tid, NULL, &pthread_log, NULL);
}

//===============================================================
//register_log
//注册日志模块
//===============================================================
void register_log(int md, const char* filepath)
{
	//fprintf(stdout, "[register_log] [%s]\n", filepath);
	unsigned int i = 0;
	struct stat st;
	char path[256] = {'\0'};
	
	if ((md < LOG_MODULE) || (md > LOG_MODULE_MAX)) {
		fprintf(stderr, "[register_log] failed, unknown module, id:[%d]\n", md);
		return;
	}
	if(access(LOG_BASE_FILE_PATH, R_OK) != 0) {
		LOG_SYSTEM("mkdir %s", LOG_BASE_FILE_PATH);
	}
	if(stat(filepath, &st) != 0) {
		open(filepath, O_CREAT|O_WRONLY|O_TRUNC);
		LOG_SYSTEM("chmod 0666 %s", filepath);
	}
	
	struct logbuffer_chain *chain = logbuffer_chain_new(DEF_LOG_BUFF_LEN);
	if (! chain) return;
	
	LOGBUFFER_LOCK_INIT(chain->lock);
	chain->file = strdup(filepath);
	g_logbuffer_chain[md] = chain;
	/* here we shoult get index first, because when user reboot system chain->next_idx = 1; */
	for (i=1; i< g_max_idx; ++i) {
		snprintf(path, sizeof(path)-1, "%s.%d", chain->file, i);
		memset(&st, 0, sizeof(st));
		if (stat(path, &st)) {
			chain->next_idx = i;	/* if not found the file, we set the next index */
			break;
		}
	}
}

void destroy_log(int md)
{
	int i=0;
	for (; i < LOG_MODULE_MAX; ++i) {
		struct logbuffer_chain *chain = g_logbuffer_chain[i];
		if ( ! chain) continue;
		
		LOGBUFFER_LOCK_DESTROY(chain->lock);
		if (chain->file) free(chain->file);
		logbuffer_chain_free(chain);	
	}
}

void write_log(int md, const char* fmt, ...)
{
	int tlen=0;
	int vlen=0;
	va_list args;
	
	int off = 0;
	int pos = 0;
	int buffer_len = 0;
	char* buffer = NULL;
	struct logbuffer_chain* chain = g_logbuffer_chain[md];
 	
	if ( ! chain) {
		fprintf(stderr, "[write_log] failed, module[%d] not exist, please init first!\n", md);
		return;
	}
 
again:	
	LOGBUFFER_LOCK_ENTER(chain->lock);
	pos = off = chain->off;
	buffer = (char*)(chain->buffer);
	buffer_len = chain->buffer_len-1;
	
	/* format time */
	if ((buffer_len - off) < DEF_SYS_TIME_LEN) goto finish;
	tlen=gettime(buffer + off, DEF_SYS_TIME_LEN);
	if (tlen<=0) goto finish;
	off += tlen;
	
	/* insert space charactor */
	if (buffer_len==off) goto finish;
	buffer[off] = ' ';
	off += 1;
	
	/* format input */	
	if (buffer_len==off) goto finish;
	va_start(args, fmt);
	vlen = vsnprintf(buffer + off, buffer_len-off, fmt, args);
	va_end(args);
	
	/* buffer is not big, we need write the log immediately */
	if (vlen <= 0 || vlen >= (buffer_len - off)) goto finish;
	
	off += vlen;
	chain->off = off;
	LOGBUFFER_LOCK_LEAVE(chain->lock);
	return;
	
finish:
	chain->off = pos;
	LOGBUFFER_LOCK_LEAVE(chain->lock);
	/* when buffer is not enough, we need write log immediately */
	do_write_log(chain);
	/* need format string again to avoid losting log */
	tlen = 0;
	vlen = 0;
	off = 0;
	pos = 0;
	buffer_len = 0;
	buffer = NULL;
	goto again;
}

static void * pthread_del_rotate_log(void *param)
{
	int i = 0;
	int k = 0;
	int new_idx = 0;
	int max_idx = 0;
	char old_path[256] = {0};
	char tmp_path[256] = {0};

	struct logbuffer_chain* chain = NULL;
	if(param == NULL){
	    return NULL;
	}
	new_idx = *((int*)param);
	max_idx = *((int*)param+1);
	if(param){
		free(param);
	}
	pthread_detach(pthread_self());
    
	for (i=0; i < LOG_MODULE_MAX; i++) { 
		chain = g_logbuffer_chain[i];
		if (!chain)  continue;
		/*删除下标在idx之后的所有日志文件*/
		snprintf(old_path, sizeof(old_path)-1, "%s.%d", chain->file, new_idx+1);
		snprintf(tmp_path, sizeof(tmp_path)-1, "%s.%d", chain->file, 1000);
		rename(old_path, tmp_path);
		unlink(tmp_path);
		for (k = new_idx+2; k <= max_idx; k++) {
			memset(old_path, 0, sizeof(old_path));
			snprintf(old_path, sizeof(old_path)-1, "%s.%d", chain->file, k);
			if (access(old_path, R_OK) == 0) {
				LOG_SYSTEM("rm -f %s", old_path);
				fprintf(stderr, "unlink log old_path [%s]\n", old_path);
			}
		}
		if(chain->next_idx > new_idx) {
		    chain->next_idx = 1;
		}			
	} 
	return NULL;	
}

void set_log_max_idx(int idx)
{
	int i = 0;
	int j = 0;
	
	struct stat st;
	size_t old_max_idx = 0;
	char tmp_path[256] = {0};
	
	pthread_t pth_id;
	struct logbuffer_chain* chain = NULL;
		
	if(idx < MIN_LOG_FILE_IDX || idx > MAX_LOG_FILE_IDX) {
		fprintf(stderr, "[set_log_max_idx] failed, idx:[%d]\n", idx);
		g_max_idx = DEF_LOG_FILE_IDX;
		return;
	}
 	if (idx == g_max_idx)
 		return;
	else if (idx < g_max_idx) {
		void *ret = malloc(8);
		if ( ! ret) return;
		*((int*)ret)= idx;
		*((int*)ret+1) = g_max_idx;
		/*创建线程删除下标超过idx的日志文件*/
		pthread_create(&pth_id, NULL, &pthread_del_rotate_log, (void*)ret);
	} else {
		old_max_idx = g_max_idx;
		for (i=0; i < LOG_MODULE_MAX; i++) { 
	  	chain = g_logbuffer_chain[i];
      if( ! chain)  continue;
      for(j=1; j<=old_max_idx; ++j) {
      	memset(&st, 0, sizeof(st));
      	memset(tmp_path, 0, sizeof(tmp_path));	
      	snprintf(tmp_path, sizeof(tmp_path)-1, "%s.%d", chain->file, j);
      	/*遍历已存在的日志文件,下标未超过g_max_idx,则退出;下标已到达g_max_idx,则继续增加next_idx*/
      	if (stat(tmp_path, &st)) break;
				else if (j==old_max_idx) chain->next_idx = old_max_idx+1;
			}
		}
	}
	g_max_idx = idx;
}

void set_log_max_size(int size)
{
	if (size<MIN_LOG_FILE_SIZE || size>MAX_LOG_FILE_SIZE) {
		fprintf(stderr, "[set_log_max_size] failed, size:[%d]\n", size);
		g_max_size = DEF_LOG_FILE_SIZE * 1024 * 1024;
		return;
	}
	g_max_size = size * 1024 *1024;
}

static int show_log_flag = 1;
static void stop_show_log_hander(int signum)
{
	if (show_log_flag == 1) {
		show_log_flag = 0;
	}
}

//===============================================================
//show_log_file_record
//显示日志文件记录
//	fname:日志文件名
//	keywords:日志类型(alarm,error,info,debug)
//	trange:日期范围(2015-06-07 17:36:21--2015-06-11 01:13:10)
//	page：
//	pageline：显示行数
//===============================================================

#define	LOGBUFSIZ	8192
int show_log_file_record(char **outbuf, const char *fname, const char *keywords, 
		const char *trange, size_t page, size_t pageline)
{
	int fd;
	size_t bytes_read = 0;
	size_t read_pos = 0;
	size_t read_left = 0;
	char *buffer_end = NULL;
	char * p = NULL;
	char *nl = NULL;
	char buf[LOGBUFSIZ] = {'\0'};
		
	char *output=NULL;
	int out_pos = 0;
	char leftbuf[256] = {'\0'};

	struct tm ftm;
	struct tm stm;
	struct tm ttm;
	time_t start_time = 0;
	time_t stop_time = 0;
	time_t check_time = 0;
	
	int flag = 0;
	
	int ret = 0;	
	int len = 0;
	const char *format = "%Y-%m-%d %H:%M:%S";
	
	if (!fname || !keywords || !trange || !pageline) {
		fprintf(stderr, "parameter wrong\n");
		return -1;
	}
	
	/* for example: 2011-10-12 12:12:20--2011-10-24 12:24:24 */	
	if (trange[0] != 0) {
		flag = 1;
		/* strptime:按照特定时间格式将字符串转换为时间类型*/
		p=(char *)strptime(trange, format, &ftm);
		if ((p == NULL) || (ftm.tm_year < 0)) {
			fprintf(stderr, "time range fomat wrong\n");
			return -1;
		}
		p = strptime(p+2, format, &stm);
		if ((p == NULL) || (stm.tm_year < 0)) {
			fprintf(stderr, "time range fomat wrong\n");
			return -1;
		}
		start_time = timegm(&ftm);
		stop_time = timegm(&stm);
	}

	if (keywords[0] != 0) {
		if (flag == 0) flag = 2;	/* query by keywords */
		else flag = 3;	/* query by keywords and time */
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		/* No such file or directory */
		if (errno == ENOENT) { 
			fprintf(stderr, "left 0 pages\n");
			return 0;
		}
		fprintf(stderr, "open file failed\n");
		return -1;
	}
	show_log_flag = 1;
	
	/*设置定时器5s*/
	alarm(0);
	signal(SIGALRM, stop_show_log_hander);
	alarm(5);

	int line=1;
	int linestart=(page-1)*pageline;
	int lineend=page*pageline;
	
	/* show all */	
	if (flag == 0) {
		while (show_log_flag) {
			p = buf;
			bytes_read = read (fd, buf + read_left, LOGBUFSIZ - read_left);
			buffer_end = buf + read_left + bytes_read;
			if (bytes_read == 0) { /* EOF */
				break;
			}
			if (bytes_read == ((size_t) -1)) { /* error */
				ret = -1;
				goto finish;
			}
			read_pos += bytes_read;
			/*在指定内存范围内查找'\n'，返回该字节指针*/
			while ((nl = (char *)memchr(p, '\n', buffer_end - p)))
			{
				++nl;
				if (nl <= buffer_end) {
					if (line > linestart && line <= lineend) {
						/* malloc memory and output the log */	
						output = (char*)realloc(output, out_pos + (nl-p) + 1);
						if (output != NULL) {
							memcpy(output+out_pos, p, nl-p);
							out_pos += (nl-p);
						}
					}
					p = nl;
					line++;
				}
			}
			read_left = buffer_end - p;
			memcpy(buf, p, read_left);
		}

		/* realloc to output left pages */
		len = snprintf(leftbuf, sizeof(leftbuf)-1, "%d\n", line-1);	
		output = (char*)realloc(output, out_pos+len+1);
		if (output != NULL) {
			memcpy(output+out_pos, leftbuf, len);
			out_pos += len;
		}
	}
	
	/* query by keywords */
	if (flag == 2) {
		while (show_log_flag) {
			p = buf;
			bytes_read = read (fd, buf + read_left, LOGBUFSIZ - read_left);
			buffer_end = buf + read_left + bytes_read;
			if (bytes_read == 0) { /* EOF */
				break;
			}
			if (bytes_read == ((size_t) -1)) { /* error */
				ret = -1;
				goto finish;
			}
			read_pos += bytes_read;
			while ((nl = (char *)memchr(p, '\n', buffer_end - p)))
			{
				if (nl < buffer_end) {
					*nl = 0;
					int i=0;
					char key[10];
					char * key_p=p+LOG_KEYWORD_POSITION;
					while(*key_p!=']')
					{
						key[i]=*key_p;
						key_p++;
						i++;
						/*防止日志文件格式被修改，程序进入死循环*/
						if(i>8){
							break;
						}		
					}
					key[i]='\0';
					if (strstr(key, keywords) == NULL) {
						p = ++nl;
						continue;
					}
					*nl++ = '\n';
					if (line > linestart && line <= lineend) {
						
						/* malloc memory and output the log */	
						output = (char*)realloc(output, out_pos + (nl-p) + 1);
						if (output != NULL) {
							memcpy(output+out_pos, p, nl-p);
							out_pos += (nl-p);
						}
					}

					p = nl;
					line++;
				}
			}
			read_left = buffer_end - p;
			memcpy(buf, p, read_left);
		}
		
		/* realloc to output left pages */
		len = snprintf(leftbuf, sizeof(leftbuf)-1, "%d\n", line-1);	
		output = (char*)realloc(output, out_pos+len+1);
		if (output != NULL) {
			memcpy(output+out_pos, leftbuf, len);
			out_pos += len;
		}
	}
	
	/* query by time */
	if (flag == 1) {
		while (show_log_flag) {
			p = buf;
			bytes_read = read (fd, buf + read_left, LOGBUFSIZ - read_left);
			buffer_end = buf + read_left + bytes_read;
			if (bytes_read == 0) { /* EOF */
				break;
			}
			if (bytes_read == ((size_t) -1)) { /* error */
				ret = -1;
				goto finish;
			}
			read_pos += bytes_read;
			while ((nl = (char *)memchr(p, '\n', buffer_end - p)))
			{
				if (nl < buffer_end) {
					*nl = 0;
					if (strptime(p+1, format, &ttm) == NULL) {
						p = ++nl;
						continue;
					}
					check_time = timegm(&ttm);
					/*compare the log time*/
					if ((check_time < start_time) || (stop_time < check_time)) {
						p = ++nl;
						continue;
					}
					*nl++ = '\n';
					if (line > linestart && line <= lineend) {
						
						/* malloc memory and output the log */	
						output = (char*)realloc(output, out_pos + (nl-p) + 1);
						if (output != NULL) {
							memcpy(output+out_pos, p, nl-p);
							out_pos += (nl-p);
						}
					}
					p = nl;
					line++;
				}
			}
			read_left = buffer_end - p;
			memcpy(buf, p, read_left);
		}
		len = snprintf(leftbuf, sizeof(leftbuf)-1, "%d\n", line-1);	
		output = (char*)realloc(output, out_pos+len+1);
		if (output != NULL) {
			memcpy(output+out_pos, leftbuf, len);
			out_pos += len;
		}

	}
	
	/* query by keywords and time */
	if (flag == 3) {
		while (show_log_flag) {
			p = buf;
			bytes_read = read (fd, buf + read_left, LOGBUFSIZ - read_left);
			buffer_end = buf + read_left + bytes_read;
			if (bytes_read == 0) { /* EOF */
				break;
			}
			if (bytes_read == ((size_t) -1)) { /* error */
				ret = -1;
				goto finish;
			}
			read_pos += bytes_read;
			while ((nl = (char *)memchr(p, '\n', buffer_end - p)))
			{
				if (nl < buffer_end) {
					*nl = 0;
					int i=0;
					char key[10];
					char * key_p=p+LOG_KEYWORD_POSITION;
					while(*key_p!=']')
					{
						key[i]=*key_p;
						key_p++;
						i++;
						/*防止日志文件格式被修改，程序进入死循环*/
						if(i>8){
							break;
						}			
					}
					key[i]='\0';
					if (strstr(key, keywords) == NULL) {
						p = ++nl;
						continue;
					}
					if (strptime(p+1, format, &ttm) == NULL) {
						p = ++nl;
						continue;
					}
					check_time = timegm(&ttm);
					
					/*compare the log time*/
					if ((check_time < start_time) || (stop_time < check_time)) {
						p = ++nl;
						continue;
					}
#ifdef COUNT_RESULT
					if (strstr(p, "[success]") != NULL) {
						count_success++;
					} else {
						count_failed++;
					}
					*nl++ = '\n';
#else
					*nl++ = '\n';
					if (line > linestart && line <= lineend) {

						/* malloc memory and output the log */	
						output = (char*)realloc(output, out_pos + (nl-p) + 1);
						if (output != NULL) {
							memcpy(output+out_pos, p, nl-p);
							out_pos += (nl-p);
						}
					}
#endif
					p = nl;
					line++;
				}
			}
			read_left = buffer_end - p;
			memcpy(buf, p, read_left);
		}
#ifdef COUNT_RESULT
		printf("success:%d failed:%d\n", count_success, count_failed);
#else
		len = snprintf(leftbuf, sizeof(leftbuf)-1, "%d\n", line-1);	
		output = (char*)realloc(output, out_pos+len+1);
		if (output != NULL) {
			memcpy(output+out_pos, leftbuf, len);
			out_pos += len;
		}
#endif
	}
	
	//定时器超时
	if (show_log_flag == 0) fprintf(stderr, "\nlog file is too large, please use keywords or time range to reduce the searching\n");
	signal(SIGALRM, SIG_IGN);

finish:
	
	show_log_flag = 0;
	close(fd);

	/* point the output buf */	
	output[out_pos] = '\0';
	*outbuf = output;
	
	return ret;
}