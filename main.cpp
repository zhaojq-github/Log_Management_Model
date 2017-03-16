#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
 #include <stdlib.h>
#include "log.h"

int main()
{
	/* log config */
	int g_nLogLevel = SYS_LOG_ALL;	//设置日志显示级别（ALM, ERR, INFO, DBG）
	int g_nForeground = 1;	//设置日志显示方式（0：后台，1：前台）
	
	/*前台日志显示 */
	fprintf(stdout, "show log_info foreground\n");
	log_alarm(getpid(), "show log_alarm...\n");
	int errno = 3;
	log_error(errno, "show log_error...\n");
	log_info(0, "show log_info...\n");
	log_debug(0, "show log_debug...\n");
	
	/*后台日志显示 */
	fprintf(stdout, "\nshow log_info background\n");
	g_nForeground = 0;
	/* init log and register log module to the list */
	init_log();
	
	/* register log */
	char log_filename[128] = {'\0'};
	memset(log_filename, 0, sizeof(log_filename));
	snprintf(log_filename, sizeof(log_filename)-1, "%s%s", LOG_BASE_FILE_PATH, LOG_FILE_NAME); 
	register_log(LOG_MODULE, log_filename);
	
	log_alarm(getpid(), "show log_alarm...\n");
	log_error(errno, "show log_error...\n");
	log_info(0, "show log_info...\n");
	log_debug(0, "show log_debug...\n");
	
	char *outbuf=NULL;
	//show_log_file_record(&outbuf, argv[1], argv[2], argv[3], atoi(argv[4]), atoi(argv[5]));
	show_log_file_record(&outbuf, log_filename, "info", "2015-06-07 17:36:21--2015-06-12 01:13:10", 1, 200);
	if (outbuf)
		printf("%s\n", outbuf);
	return 0;
}
