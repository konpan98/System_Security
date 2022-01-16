#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

void writeLogFile(char * info){
	  FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)("file_logging.log", "a");

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(info, 1, strlen(info), original_fopen_ret);


}


void logEntryFill(FILE* fp,const char* path,const char * mode){
	unsigned int uid;
	char info[1200];
	char pathName[500];
	char datestr[200];
	char timestr[200];

	//char  * timestr;
	int access_type;
	int is_action_denied;

	/////uid//////////
	uid=getuid();

	//////////path and name///////////
	realpath(path,pathName);
	//////time//////////
	time_t rawtime;
    struct tm * timeinfo;
    time (&rawtime);
    timeinfo = localtime (&rawtime);
    strftime(timestr,sizeof(timestr),"%T",timeinfo);
    //timestr=asctime(timeinfo);
	/////date/////////
    strftime(datestr,sizeof(datestr),"%F",timeinfo);
    ///////access_type//////////////////
    if(*mode == (char)'w'  ){
    	access_type=0;
    }
    else if(*mode == (char)'r'){
    	access_type=1;
    }
    else{

    	access_type=2;
    }
    /////////is_action_denied/////////////
    if(fp != NULL){
    	is_action_denied = 0;
    }
    else{
    	is_action_denied = 1;
    }
    ////////////file fingerprint /////////////////
    unsigned char c[MD5_DIGEST_LENGTH];
    
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, fp)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) 
    	printf("%02x", c[i]);
    //////////concatenate information////////////////////
    sprintf(info,"Uid : %d  ,Path and Name : %s ,Time : %s ,Date : %s  ,Access type : %d   ,IsActionDenied : %d,File fingerprint : %s\n",uid,pathName,timestr,datestr,access_type,is_action_denied,c);
    printf("log info %s ",info) ;

    /////write to log file ////////////////////
    writeLogFile(info);
  
   /* FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)("file_logging.log", "a");

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(info, 1, strlen(info), original_fopen_ret);*/

}



FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	logEntryFill(original_fopen_ret,path,mode);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	int fno = fileno(stream);
	char proclnk[100];
	char filename[100];
	ssize_t r;
	sprintf(proclnk, "/proc/self/fd/%d", fno);
	r = readlink(proclnk, filename, 100);
	filename[r] = '\0';
	//printf("%s",filename);
	logEntryFill(stream,filename,"nothing");

	return original_fwrite_ret;
}


