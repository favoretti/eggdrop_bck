#include <stdio.h>
#include <db.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#define DEBUG

char dbloc[255];
int dbcustomloc = 0;

void list_bots();

void usage(char *progname)
{
  printf("Usage: %s <-l | -h | -f <pid> | -r <pid> | -u <user> | -d <database>\n", progname);
}

void find_bots_pid_uid_handlen(int number)
{
  printf("foo\n");
}

void find_bots_username(char *user)
{
  printf("bar %s\n", user);
}

int main(int argc, char **argv)
{
  extern char *optarg;
  extern int optind;
  int c;

  if(argc < 2)
    {
      usage(argv[0]);
      return 0;
    }
  
  while((c = getopt(argc, argv, "hlr:f:u:d:")) > 0) // we've got an option
    {
      // -l = list bots
      // -f x = find x
      // -r x = remove pid <x> from database
      // -u x = list bots of user <x>
      switch(c)
        {
            
          case 'r':
            fprintf(stderr, "%s", optarg);
            break;
            
          case 'u':
            fprintf(stderr, "%s", optarg);
            break;

          case 'd':
            fprintf(stderr, "%s", optarg);
            if(strlen(dbloc) > 254)
              {
                printf("Too long.\n");
                return 1;
              }
            dbcustomloc = 1;
            strcpy(dbloc, optarg);
            break;
            
          case 'f':
            fprintf(stderr, "%s", optarg);
            break;

          case 'l':
            list_bots();
            break;

          case 'h':
          default:
            usage(argv[0]);
            break;
        }
    }

  return 1;
}

void list_bots()
{
  DB *dbp;
  DBT key, data;
  DBC *cursorp;
  u_int32_t flags;
  int ret;
  int pid = 0;
  int uid;
  int handlen;
  char config[255];
  int count = 0;
  
  ret = db_create(&dbp, NULL, 0);
  if(ret != 0)
    {
      printf("Can't create database handle!\n");
      return;
    }
  
  flags = DB_RDONLY;
 
  if(dbcustomloc == 1)
    {
      ret = dbp->open(dbp, NULL, dbloc, NULL, DB_BTREE, flags, 0);
    }
  else
    {
      ret = dbp->open(dbp, NULL, "/root/bck/bck.db", NULL, DB_BTREE, flags, 0);    
    }
  
  if(ret != 0)
    {
      printf("Can't open database!\n");
      return;
    }
  
  dbp->cursor(dbp, NULL, &cursorp, 0);

  memset(&key, 0, sizeof(DBT));
  memset(&data, 0, sizeof(DBT));
  
  key.data = &pid;
  key.ulen = sizeof(int);
  key.flags = DB_DBT_USERMEM;

  printf(" PID    UID HL CONFIG\n");
  
  while ((ret = cursorp->c_get(cursorp, &key, &data, DB_NEXT)) == 0)
    {
      if(sscanf((char *)data.data, "%d#%d#%s", &uid, &handlen, config) == 3)
        printf("%-5d %-5d %-2d %s\n", uid, pid, handlen, config);
      else
        printf("sscanf failed\n");
      
      //      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      count++;
    }
  
  printf("Total: %d bots\n", count);
  
  /* Cursors must be closed */
  if (cursorp != NULL)
    cursorp->c_close(cursorp);
  
  if (dbp != NULL)
    dbp->close(dbp, 0);
  
  return;
}
