#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char * date; /* file access date */
	char * time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}



struct entry split_line(char * line){
	struct entry logEntry;
	char *uid;
	char access_type[20],action_denied[20];
	char * pathName;
	char * date;
	char * time;
    char * fingerprint;


    char * ptr =strtok(line,",");
    uid=ptr;
    ptr =strtok(NULL,",");
    pathName=ptr;
    ptr =strtok(NULL,",");
    time=ptr;
    ptr =strtok(NULL,",");
    date=ptr;
    ptr =strtok(NULL,",");
    sprintf(access_type,"%s",ptr);
    ptr =strtok(NULL,",");
    sprintf(action_denied,"%s",ptr);
    ptr =strtok(NULL,",");
    fingerprint=ptr;


    /////uid/////////
  
    char * ptr1= strtok(uid,":");
    ptr1 = strtok(NULL, ":");
    //printf("%s\n",ptr1 );
    logEntry.uid=atoi(ptr1);


    //////path and name///////
   
    char* ptr2 = strtok(pathName,":");
    ptr2 = strtok(NULL, ":");
   // printf("%s\n",ptr2);
    logEntry.file=ptr2;

    ////time //////////////
   
    char * ptr3 = strtok(time,":");
    ptr3 = strtok(NULL, ":");
   // printf("%s\n",ptr3);
    logEntry.time=ptr3;


    ////date//////////////
   
    char* ptr4 = strtok(date,":");
    ptr4 = strtok(NULL, ":");
   // printf("%s\n",ptr4 );
    logEntry.date=ptr4;

    ////access type/////
   
    char* ptr5 = strtok(access_type,":");
    ptr5 = strtok(NULL, ":");
    //printf("%s\n",ptr5 );
    logEntry.access_type=atoi(ptr5);

    ////action denied/////
  
    char* ptr6 = strtok(action_denied,":");
    ptr6 = strtok(NULL, ":");
   // printf("%s\n",ptr6 );
    logEntry.action_denied=atoi(ptr6);

    ////file fingerprint///////
   
    char *ptr7 = strtok(fingerprint,":");
    ptr7 = strtok(NULL, ":");
    //printf("%s\n",ptr7 );
    logEntry.fingerprint=ptr7;

   // printf (" uid %d, pathname %s, time %s ,date %s , acc %d ,action %d,fingerprint %s ",logEntry.uid,logEntry.file,logEntry.time,logEntry.date,logEntry.access_type,logEntry.action_denied,logEntry.fingerprint);

    return logEntry;



}

struct entry* parse_log(FILE *log,int * entries){
	if(log == NULL )
		printf("file not open\n");
	size_t numOfEntries=0;
	int counter = 0;
	int line_counter= 0;
	char * splitPtr;
	char line[300];

	for (char c = getc(log); c != EOF; c = getc(log)){
        if (c == '\n') 
            numOfEntries++;
	}

    struct entry * logEntries = malloc(numOfEntries*(sizeof(struct entry)));
    fseek(log,0,SEEK_SET);
    for (char c = getc(log); c != EOF; c = getc(log)){
        if (c == '\n') {
        	logEntries[counter]=split_line(line);
            line_counter=0;
            counter++;
        }
        line[line_counter]= c;
        line_counter++;
	}
	*entries = counter;
	return logEntries;
}



void 
list_unauthorized_accesses(FILE *log)
{
	int numberOfEntries;
	struct entry * logs = parse_log(log,&numberOfEntries);
	int uids[numberOfEntries];
	int malicious[numOfEntries];
	for(int i = 0; i<numOfEntries; i++){
		if(logs[i].action_denied == 1){
			
		}
	}
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
