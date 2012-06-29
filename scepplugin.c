#include "./include/scepplugin.h"

FILE* fh;

int RCMSCEP_Initialize(int* iVersion,void* reserved)
{
  char fname[]="/usr/rsa/online/RSA/RSA_CM/WebServer/scep-server/newcheck/passdata";
  fh = fopen(fname,"r");
  openlog("scepplugin.so",LOG_CONS|LOG_NOWAIT,LOG_AUTHPRIV);
  syslog(LOG_INFO,"Plugin loading");
  if(fh == NULL)
  {
    error(0,errno,"Error occured");
    syslog(LOG_INFO,"Plugin loading failed!");
    return RCMSCEP_REFUSE;
  }
  syslog(LOG_INFO,"Plugin loading success!");
  return RCMSCEP_SUCCESS;
}

int RCMSCEP_CheckAuthorization(SCEPReqInfo* reqInfo)
{
  struct passentry* entry;
  int retval = 0;
  entry = (struct passentry*)malloc(sizeof(struct passentry));
  entry->uid = reqInfo->_IPADDRESS;
  entry->password = reqInfo->_PASSWORD;
  syslog(LOG_INFO,"Looking up user %s and pass %s",entry->password,entry->uid);
  retval = verifypass(entry,fh);
  syslog(LOG_INFO,"verify function returned %d",retval);
  fclose(fh);
  closelog();
  free(entry);
  return retval;
}

int verifypass(struct passentry* inpass,FILE* passdata)
{
  char outhash[BCRYPT_HASHSIZE];
  char* currline;
  currline = (char*)malloc(MAXBUF);
  int retval = 0;
  syslog(LOG_INFO,"Invoking verifypass");
  while(fgets(currline,MAXBUF,passdata) != NULL)
  {
    currline[strnlen(currline,MAXBUF) - 1] = '\0';
    syslog(LOG_INFO,"Comparing line |%s| with |%s|",currline,inpass->uid);
    if(strncmp(inpass->uid,currline,MAXBUF) == 0)
    {
      syslog(LOG_INFO,"Found match! %s\n",currline);
      if(fgets(currline,MAXBUF,passdata) != NULL)
      {
        currline[strnlen(currline,MAXBUF) - 1] = '\0';
        retval = bcrypt_hashpw(inpass->password,currline,outhash); 
        if(retval == 0)
        {
          if(strncmp(currline,outhash,MAXBUF) == 0)
          {
            syslog(LOG_INFO,"Password for %s was correct!",inpass->uid);
            retval = RCMSCEP_AUTHORIZE;
          }
          else
          {
            syslog(LOG_INFO,"Password for %s was INCORRECT!",inpass->uid);
            retval = RCMSCEP_REFUSE;
          }
        }
      }
      break;
    }
  }
  free(currline);
  return retval;
}
