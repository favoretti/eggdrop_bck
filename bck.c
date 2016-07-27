/*
 *  Automated bot checker. 
 * 
 * v 0.01 - Basic functionality in place, including BDB data storage.
 * v 0.02 - Connection timeout has been impemented for losers who connect to our botchk and do nothing
 * v 0.03 - Implemented timeout between restarts to not to drop box dead when a few hundreds of drops start up
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <resolv.h>
#include <time.h>
#include <string.h>
#include <pwd.h>
#include <signal.h>
#include <db.h>
#include <libgen.h>
#include <sys/wait.h>

/* Port, where your botchk will be responding, 
 if you change this, change eggdrop src too */
#define PORT 1023

/* Don't change this :) */
#define REGISTER_OK "200 ok\n"

/* Location of eggdrop binary with handlen 9 */
#define BOTLOCATION "/hosting/eggdrop/eggdrop"
#define BOTBINNAME "eggdrop"

/* Location of eggdrop binary with handlen 32 */
#define BOTLOCATION32 "/hosting/eggdrop32/eggdrop"
#define BOTBINNAME32 "eggdrop"

/* Location of the database which stores bots info over botchk restarts */
#define DBLOCATION "/root/bck/bck.db"   

/* Maximum amount of simultaneous connections to botchk */
#define MAXCONN 500       

/* Maximum amount of simultaneously running bots */
#define MAXBOTS 1024

/* Some more debugging messages to logging, 
 you probably don't want this */
#undef DEBUG

int fd; // listening socket
int high_fd; // highest socket for select()
int connectlist[MAXCONN];
int connecttime[MAXCONN];
fd_set socks;

int count = 0;
int last_restart = 0;
extern char **environ;

// flags
int flag_reread_bdb = 0;

struct bot_data {
  int uid;
  int pid;
  char config[80];
  int restarts;
  int handlen;
};

struct bot_data bots_data[MAXBOTS];

int daemon_init(void)
{
  pid_t pid;
  int i;
  

  if ((pid = fork()) < 0) 
    {
      return -1;
    } 
  else if (pid != 0) 
    {
      exit(0);
    }

  for (i=getdtablesize();i>=0;--i) close(i);
  i = open("/dev/null", O_RDWR); /* open stdin */
  dup(i); /* stdout */
  dup(i); /* stderr */
  
  setsid();
  return 0;
}

void close_sock(int listnum)
{
  close(connectlist[listnum]);
  connectlist[listnum] = 0;
  connecttime[listnum] = 0;
}

void setnonblocking(sock)
  int sock;
{
  int opts;
  
  opts = fcntl(sock, F_GETFL);
  
  if (opts < 0) 
    {
      syslog(LOG_ERR, "fcntl(F_GETFL) failed");
      exit(EXIT_FAILURE);
    }
  
  opts = (opts | O_NONBLOCK);
  
  if (fcntl(sock, F_SETFL, opts) < 0) 
    {
      syslog(LOG_ERR, "fcntl(F_SETFL) failed");
      exit(EXIT_FAILURE);
    }
  
  return;
}

void send_data(char *data, int *listnum)
{
  if(send(connectlist[*listnum], data, strlen(data), MSG_NOSIGNAL) < 0)
    {
      syslog(LOG_ERR, "Couldn't write to socket %d: %s", connectlist[*listnum], strerror(errno));
      close_sock(*listnum);
      return;
    }
  return;
}

int check_pid_uid(int *pid, int *my_uid)
{
  struct stat buf;
  char procfilename[80];
  int res;
  
  if(*pid < 0 || *pid > 65535)
    return -1;
  
  sprintf(procfilename, "/proc/%d/status", *pid);
  
  res = stat(procfilename, &buf);
  
  if(res < 0)
    return -1;
  
  if(buf.st_uid == *my_uid)
    return 0;
  else
    return -1;
}

int check_data_validity(int *uid, int *pid, char *conf, int *listnum, int *handlen)
{
  struct stat finfo;
  int res;
  char temp[255];
  
  if(*handlen != 9 && *handlen != 32)
    {
      send_data("100 Wrong handlen, rejecting.\n", listnum);
      return -1;
    }
  
  if(*uid < 100) // probably some hack
    {
      send_data("100 Too low UID, can't do, sorry.\n", listnum);
      return -1;
    }
  
  if(!getpwuid(*uid)) // no such ID found, a hack, a hack!
    {
      sprintf(temp, "100 Can't find your UID (%d), are you a hacker?\n", *uid);
      send_data(temp, listnum);
      return -1;
    }
  
  if(*pid < 1) // hackers again? :)
    {
      send_data("100 What, a wrong PID? You're definitely a hacker\n", listnum);
      return -1;
    }
  
  if(*pid > 65535)
    {
      send_data("100 Go away, you're trying to break me\n", listnum);
      return -1;
    }
  
  if(kill(*pid, 0) == -1) // no such pid running, huh?
    {
      send_data("100 I can't find your pid, you're trying to fool me again!\n", listnum);
      return -1;
    }
  
  if(check_pid_uid(pid, uid) < 0)
    {
      send_data("100 This PID doesn't belong to your UID, bad, bad hacker\n", listnum);
      return -1;
    }
  
  res = stat(conf, &finfo);
  
  if(res < 0)
    {
      send_data("100 Can't find the config file, are you hacking me again?\n", listnum);
      return -1;
    }
  
  if(!S_ISREG(finfo.st_mode))
    {
      send_data("100 Your config file is not a file, you, nasty hacker\n", listnum);
      return -1;
    }

  // No errors found
  return 0;
}

int register_db(int *pid, int *uid, char *config, int *handlen)
{
  DB *dbp;
  DBT key, data;
  u_int32_t flags;
  int ret;
  char tmp[256];
  
  ret = db_create(&dbp, NULL, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Can't create database handle!");
      return -1;
    }
  
  flags = DB_CREATE;

  ret = dbp->open(dbp, NULL, DBLOCATION, NULL, DB_BTREE, flags, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Can't open database!");
      return -1;
    }

  memset(&key, 0, sizeof(DBT));
  memset(&data, 0, sizeof(DBT));

  key.data = pid;
  key.size = sizeof(int);

  sprintf(tmp, "%d#%d#%s", *uid, *handlen, config);
  data.data = tmp;
  data.size = strlen(tmp) + 1;
  
  ret = dbp->put(dbp, NULL, &key, &data, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Couldn't store data to the database!");
      return -1;
    }

  if(dbp != NULL)
    dbp->close(dbp, 0);

  syslog(LOG_INFO, "Registered pid %d", *pid);
  
  return 0;
}

int unregister_db(int pid)
{
  DB *dbp;
  DBT key;
  u_int32_t flags;
  int ret;
  
  ret = db_create(&dbp, NULL, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Can't create database handle!");
      return -1;
    }
  
  flags = DB_CREATE;

  ret = dbp->open(dbp, NULL, DBLOCATION, NULL, DB_BTREE, flags, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Can't open database!");
      return -1;
    }

  memset(&key, 0, sizeof(DBT));

  key.data = &pid;
  key.size = sizeof(int);

  ret = dbp->del(dbp, NULL, &key, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Warning: Couldn't remove data from the database!");
      return -1;
    }

  if(dbp != NULL)
    dbp->close(dbp, 0);

  syslog(LOG_INFO, "Unregistered pid %d", pid);
  
  return 0;
}

int read_bdb()
{
  DB *dbp;
  DBT key, data;
  DBC *cursorp;
  u_int32_t flags;
  int ret;
  int pid = 0;
  int uid;
  int handlen;
  int i = 0;
  char config[255];

  ret = db_create(&dbp, NULL, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Can't create database handle!");
      return -1;
    }

  flags = DB_CREATE;

  ret = dbp->open(dbp, NULL, DBLOCATION, NULL, DB_BTREE, flags, 0);
  if(ret != 0)
    {
      syslog(LOG_ERR, "Can't open database!");
      return -1;
    }

  dbp->cursor(dbp, NULL, &cursorp, 0); 

  memset(&key, 0, sizeof(DBT));
  memset(&data, 0, sizeof(DBT));

  key.data = &pid;
  key.ulen = sizeof(int);
  key.flags = DB_DBT_USERMEM;

  while ((ret = cursorp->c_get(cursorp, &key, &data, DB_NEXT)) == 0) 
    {
      bots_data[i].pid = pid;
#ifdef DEBUG
      syslog(LOG_DEBUG, "Retreived %s from BDB", (char *)data.data);
#endif
      (void) sscanf((char *)data.data, "%d#%d#%s", &uid, &handlen, config);
      bots_data[i].uid = uid;
      bots_data[i].handlen = handlen;
      (void) strcpy(bots_data[i].config, config);
#ifdef DEBUG
      syslog(LOG_DEBUG, "Hence, uid: %d", uid);
      syslog(LOG_DEBUG, "config: %s", config);
      syslog(LOG_DEBUG, "handlen: %d", handlen);
#endif
//      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      i++;
      count++;
    }

  syslog(LOG_INFO, "Initialized DB, read %d entries", count);

  /* Cursors must be closed */
  if (cursorp != NULL) 
    cursorp->c_close(cursorp); 

  if (dbp != NULL) 
    dbp->close(dbp, 0);
  
  return 0;
}

void deal_with_data(int listnum) 
{
  char buffer[80];     /* Buffer for socket reads */
  ssize_t bread;
  int uid, pid, handlen;
  char conf[80];
  char cmd[80];
  int cmdpid;

  memset(&buffer, 0, sizeof(buffer));

  bread = read(connectlist[listnum], buffer, 80);
  if (bread < 0) 
    {
      /* Connection closed, close this end
         and free up entry in connectlist */
      syslog(LOG_WARNING, "Connection lost: FD=%d;  Slot=%d\n",
             connectlist[listnum],listnum);

      close_sock(listnum);
    } 
  else 
    {
      if(bread == 0)
        {
          //syslog(LOG_ERR, "read nothing, socket is gone?");
          close_sock(listnum);
          return;
        }
      
      if(sscanf(buffer, "%d#%d#%d#%79s", &pid, &uid, &handlen, conf) == 4)
        {
#ifdef DEBUG
          syslog(LOG_DEBUG, "Got UID: %d, PID: %d, handlen: %d, config: %s", uid, pid, handlen, conf);
#endif          
          // some data was invalid, wait for another attempt
          if(check_data_validity(&uid, &pid, conf, &listnum, &handlen) < 0)
            {
              syslog(LOG_DEBUG, "Got garbage data, won't re-register!");
              return;
            }
          
          int a = 0;
          int i = 0;
          
          while(bots_data[i].pid != 0 && i < MAXBOTS)
            {
              if(bots_data[i].pid == pid && bots_data[i].uid == uid &&
                 strcmp(bots_data[i].config, conf) == 0) //should theoretically never happen
                {
                  send_data("104 You're already registered, rejecting\n", &listnum);
                  return;
                }
              
              if(bots_data[i].pid != pid && bots_data[i].uid == uid && 
                 strcmp(bots_data[i].config, conf) == 0)
                {
                  if(bots_data[i].pid != -1)
                    {
                      if(kill(bots_data[i].pid, 0) == 0)
                        {
                          syslog(LOG_ERR, "Error, got duplicate. new PID: %d, old PID: %d, UID: %d", pid, bots_data[i].pid, uid);
                          send_data("104 Duplicate\n", &listnum);
                          return;
                        }
                    }
#ifdef DEBUG            
                  syslog(LOG_DEBUG, "Bot of user %d came to re-register", uid);
#endif
                  unregister_db(bots_data[i].pid);
                  register_db(&pid, &uid, conf, &handlen);
                  send_data(REGISTER_OK, &listnum);
                  bots_data[i].pid = pid;
                  return;
                }
              i++;
            }
          
          while(bots_data[a].pid != -1 && bots_data[a].pid != 0 && a < MAXBOTS)
            a++;
          
          if(a < count) // we found and empty spot
            {
              bots_data[a].pid = pid;
              bots_data[a].uid = uid;
              bots_data[a].handlen = handlen;
              strcpy(bots_data[a].config, conf);
              register_db(&pid, &uid, conf, &handlen);
              send_data(REGISTER_OK, &listnum);
              return;
            }
          
          if(count > MAXBOTS-1)
            {
              send_data("103 No space in the structure, come back later\n", &listnum);
              return;
            }
          
          // no epmty slots found, adding to the structure.
          bots_data[count].uid = uid;
          bots_data[count].pid = pid;
          bots_data[count].handlen = handlen;
          bots_data[count].restarts = 0;
          strcpy(bots_data[count].config, conf);
          count++;
          register_db(&pid, &uid, conf, &handlen);
          send_data(REGISTER_OK, &listnum);
          
        }
      else if(sscanf(buffer, "%s %d", cmd, &cmdpid) == 2)
        {
          if(strcmp(cmd, "unreg") == 0)
            {
              int a = 0;
              int _u_flag = 0;
              
              while(bots_data[a].pid != 0 && a < MAXBOTS)
                {
                  if(bots_data[a].pid == cmdpid)
                    {
                      bots_data[a].pid = -1;
                      unregister_db(cmdpid);
                      send_data("666 Bot has been unregistered.\n", &listnum);
                      _u_flag = 1;
                      break;
                    }
                  a++;
                }
              if(!_u_flag)
                send_data("999 No such PID found.\n", &listnum);
            }
        }
      else if(sscanf(buffer, "%s", cmd) == 1)
        {
          if(strncmp(cmd, "print", 3) == 0)
            {
              int a;
              char temp[1024], temp2[1024];

              sprintf(temp, "L:%d\n", count);
              send_data(temp, &listnum);
              for(a = 0; a < count; a++)
//              for(a = 0; a < 10; a++)
                {
                  sprintf(temp2, "%d#%d#%d#%d#%s\n", a, bots_data[a].uid,
                          bots_data[a].pid, bots_data[a].handlen, bots_data[a].config);
                  send_data(temp2, &listnum);
                }
              send_data("200 OK\n", &listnum);
              return;

            }
          if(strcmp(cmd, "quit") == 0)
            {
              send_data("Goodbye!\n", &listnum);
              close_sock(listnum);
              return;
            }
          send_data("100 Wrong input received\n", &listnum);
        }
      else
        {
          send_data("100 Wrong input recieved\n", &listnum);
        }
    }
}

void build_select_list() 
{
  int listnum;
  
  FD_ZERO(&socks);
  FD_SET(fd, &socks);
  
  for (listnum = 0; listnum < MAXCONN; listnum++) 
    {
      if (connectlist[listnum] != 0) 
        {
          FD_SET(connectlist[listnum], &socks);
          if (connectlist[listnum] > high_fd)
            high_fd = connectlist[listnum];
        }
    }
}

void handle_new_connection() 
{
  int listnum;
  int connection;
  
  /* We have a new connection coming in!  We'll
     try to find a spot for it in connectlist. */
  connection = accept(fd, NULL, NULL);
  
  if (connection < 0) 
    {
      syslog(LOG_ERR, "Connection accept failed.");
      exit(EXIT_FAILURE);
    }
  
  setnonblocking(connection);
  
  for (listnum = 0; (listnum < MAXCONN) && (connection != -1); listnum ++)
    if (connectlist[listnum] == 0) 
      {
        connectlist[listnum] = connection;
        connecttime[listnum] = time(NULL);
        connection = -1;
      }

  if (connection != -1) 
    {
      /* No room left in the queue! */
      syslog(LOG_WARNING, "No room left for new client.");

      char foo[50];
      sprintf(foo, "Sorry, this server is too busy. Try again later!\n");
      send(connection, foo, strlen(foo), 0);
      close(connection);
    }
}

void read_socket() 
{
  int listnum;
  
  /* OK, now socks will be set with whatever socket(s)
     are ready for reading.  Lets first check our
     "listening" socket, and then check the sockets
     in connectlist. */
  
  /* If a client is trying to connect() to our listening
     socket, select() will consider that as the socket
     being 'readable'. Thus, if the listening socket is
     part of the fd_set, we need to accept a new connection. */
  
  if (FD_ISSET(fd, &socks))
    handle_new_connection();
  /* Now check connectlist for available data */
  
  /* Run through our sockets and check to see if anything
     happened with them, if so 'service' them. */
  
  for (listnum = 0; listnum < MAXCONN; listnum++) 
    {
      if (FD_ISSET(connectlist[listnum], &socks))
        {
          connecttime[listnum] = time(NULL);
          deal_with_data(listnum);
        } /* for (all entries in queue) */
    }
}

int create_socket()
{
  struct sockaddr_in sin;

  int reuse_addr = 1;

  fd = socket(AF_INET, SOCK_STREAM, 0);

  if(fd < 0)
    {
      syslog(LOG_ERR, "Can't create socket!");
      return -1;
    }

  syslog(LOG_INFO, "Socket created, fd: %d", fd);

  /* So that we can re-bind to it without TIME_WAIT problems */
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
             sizeof(reuse_addr));

  setnonblocking(fd);

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(PORT);

  /* bind the socket to the port number */
  if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) 
    {
      syslog(LOG_ERR, "Couldn't bind to socket");
      close(fd);
      return -1;
    }

  listen(fd, MAXCONN);

  high_fd = fd;

  memset((char *) &connectlist, 0, sizeof(connectlist));
  return 1;
}


/***********************************************************************************/
void build_user_environment(int *uid)
{
  struct passwd *pwinfo;
  char *username, *home, *logname, *mail, *path, *term, *user;
  int userlen;
  
  pwinfo = getpwuid(*uid);
  
  if(!pwinfo)
    {
      syslog(LOG_ERR, "Can't get userinfo on uid %d", *uid);
      return;
    }
  
  username = pwinfo->pw_name;
  userlen = strlen(username);
  
  syslog(LOG_INFO, "UID: %d, username: %s", *uid, username);

  home = (char *) malloc(14 + userlen);
  logname = (char *) malloc(8 + userlen);
  mail = (char *) malloc(15 + userlen);
  path = (char *) malloc(67 + userlen);
  term = (char *) malloc(10);
  user = (char *) malloc(5 + userlen);
  
  sprintf(home, "HOME=/hosting/%s", username);
  sprintf(logname, "LOGNAME=%s", username);
  sprintf(mail, "MAIL=/var/mail/%s", username);
  sprintf(path, "/usr/local/bin:/usr/bin:/bin:/usr/bin/X11:/usr/games:/hosting/%s/bin", username);
  sprintf(term, "TERM=linux");
  sprintf(user, "USER=%s", username);
  
#ifdef DEBUG
  syslog(LOG_DEBUG, "home: %s, logname: %s, mail: %s, path: %s, term: %s, user: %s", home, logname, mail, path, term, user);
#endif
  
  if(clearenv())
    {
      syslog(LOG_ERR, "Couldn't clear environment!");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  if(putenv(home))
    {
      syslog(LOG_ERR, "Couldn't set HOME");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  if(putenv(logname))
    {
      syslog(LOG_ERR, "Couldn't set LOGNAME");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  if(putenv(mail))
    {
      syslog(LOG_ERR, "Couldn't set MAIL");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  if(putenv(path))
    {
      syslog(LOG_ERR, "Couldn't set PATH");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  if(putenv(term))
    {
      syslog(LOG_ERR, "Coulnd't set TERM");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  if(putenv(user))
    {
      syslog(LOG_ERR, "Couldn't set USER");
      free(home); free(logname); free(mail); free(path); free(term); free(user);
      return;
    }
  
  free(home); free(logname); free(mail); free(path); free(term); free(user);
  return;
}


void check_bots()
{
  int i;
  pid_t pid;
  struct passwd *pwinfo;
  
  i = 0;

  
  while (bots_data[i].pid != 0)
    {
      if(bots_data[i].pid > 99 && bots_data[i].pid != -1)
        {
#ifdef DEBUG
          syslog(LOG_DEBUG, "Checking pid: %d", bots_data[i].pid);
#endif
          if(kill(bots_data[i].pid, 0) == -1) // we lost him
            {
              // timeout
              if(time(NULL) < last_restart+5)
                {
#ifdef DEBUG
                  syslog(LOG_DEBUG, "Timeout not reached, more bots to restart.");
#endif
                  return;
                }

              // if we tried 5 times, we give up
              if(bots_data[i].restarts == 5)
                {
                  syslog(LOG_WARNING, "Tried to restart bot of user %d with config %s too many times, giving up.",
                         bots_data[i].uid, bots_data[i].config);
                  unregister_db(bots_data[i].pid);
                  bots_data[i].pid = -1;
                  bots_data[i].restarts = 0;
                  continue;
                }

              pwinfo = getpwuid(bots_data[i].uid);
              syslog(LOG_WARNING, "Checking user %d.", bots_data[i].uid);

              if(pwinfo == NULL)
                {
                  syslog(LOG_WARNING, "User with uid %d was not found, probably deleted, unregistering bot.", bots_data[i].uid);
                  unregister_db(bots_data[i].pid);
                  bots_data[i].pid = -1;
                  bots_data[i].restarts = 0;
                  continue;
                }

              if(!strcmp(pwinfo->pw_shell, "/bin/false")) 
                {
                  syslog(LOG_WARNING, "User %d has his shell set to /bin/false, not restarting the bot.", bots_data[i].uid);
                  unregister_db(bots_data[i].pid);
                  bots_data[i].pid = -1;
                  bots_data[i].restarts = 0;
                  continue;
                }


              last_restart = time(NULL);
              syslog(LOG_INFO, "Bot of user %d with pid %d is gone, restarting using %s, try #%d", bots_data[i].uid,
                     bots_data[i].pid, bots_data[i].config, bots_data[i].restarts);

              bots_data[i].restarts++;

              if((pid = fork()) < 0)
                {
                  syslog(LOG_ERR, "Couldn't fork, can't restart bot, UID:%d, PID:%d, config:%s", 
                         bots_data[i].uid, bots_data[i].pid, bots_data[i].config);
                  return;
                }
              else
                {
                  if(pid == 0)
                    {
                      int e;
                      
                      for (e=getdtablesize();e>=0;--e) close(e);
                      e = open("/dev/null", O_RDWR); /* open stdin */
                      dup(e); /* stdout */
                      dup(e); /* stderr */
                      
                      if(setsid() < 0)
                        {
                          syslog(LOG_ERR, "Can't setsid, exiting.");
                          exit (0);
                        }
                      
                      size_t len;
                      
                      len = strlen(bots_data[i].config);
                      while(bots_data[i].config[len] != '/')
                        len--;
                      
                      if(bots_data[i].config[len-1] == '.' && bots_data[i].config[len-2] == '/')
                        len = len - 2;

                      char *mydir;
                      mydir = (char *) malloc(len+1);
#ifdef DEBUG                      
                      syslog(LOG_DEBUG, "Config: %s, len: %d", bots_data[i].config, (int)len);
#endif
                      strncpy(mydir, bots_data[i].config, len);
                      mydir[len] = '\0';
#ifdef DEBUG                      
                      syslog(LOG_DEBUG, "My directory: %s", mydir);
#endif
                      if(chdir(mydir) == -1)
                        {
                          syslog(LOG_ERR, "Can't chdir() %s", strerror(errno));
                          exit(0);
                        }
                      
                      free(mydir);
                      // we're in child
                      if(setuid(bots_data[i].uid) < 0)
                        {
                          syslog(LOG_ERR, "Can't set proper uid, uid: %d (%s)", bots_data[i].uid, strerror(errno));
                          exit(-1);
                        }

                      build_user_environment(&bots_data[i].uid);
                      
                      if(bots_data[i].handlen == 9)
                        {
                          if(execl(BOTLOCATION, BOTBINNAME, bots_data[i].config, (char *)NULL))
                            {
                              syslog(LOG_ERR, "Can't launch the bot, uid %d, config: %s (%s)", 
                                     bots_data[i].uid, bots_data[i].config, strerror(errno));
                              exit(-1);
                            }
                        }
                      
                      if(bots_data[i].handlen == 32)
                        {
                          syslog(LOG_DEBUG, "Config: %s", bots_data[i].config);
                          if(execl(BOTLOCATION32, BOTBINNAME32, bots_data[i].config, (char *)NULL))
                            {
                              syslog(LOG_ERR, "Can't launch the bot, uid %d, config: %s (%s)", 
                                     bots_data[i].uid, bots_data[i].config, strerror(errno));
                              exit(-1);
                            }
                        }
                    }
#ifdef DEBUG
                  syslog(LOG_DEBUG, "Eggdrop of user %d restarted old pid: %d", bots_data[i].uid,
                         bots_data[i].pid);
#endif
                }
            }
          else
            {
              bots_data[i].restarts = 0; // successfully restarted
            }
        }
      i++;
    }
}

void handler(int signum)
{
  if(signum == SIGTERM)
    {
      syslog(LOG_INFO, "Got SIGTERM, exiting.");
      exit(0);
    }

  if(signum == SIGHUP)
    {
      syslog(LOG_INFO, "Re-reading database.");
      flag_reread_bdb = 1;
    }
}

int main(int argc, char* argv[])
{
  int ret;
  struct timeval timeout;
  int readsocks;
  int listnum;
  time_t mytime, newtime;
  struct sigaction act;


  sigaction(SIGHUP, NULL, &act);
  if(act.sa_handler != SIG_IGN)
    {
      memset(&act, 0, sizeof(act));
      act.sa_handler = handler;
      act.sa_flags = SA_RESTART;
      sigemptyset(&act.sa_mask);
      sigaction(SIGHUP, &act, NULL);
    }

  sigaction(SIGTERM, NULL, &act);
  if(act.sa_handler != SIG_IGN)
    {
      memset(&act, 0, sizeof(act));
      act.sa_handler = handler;
      sigemptyset(&act.sa_mask);
      sigaction(SIGTERM, &act, NULL);
    } 

  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_DFL;
  act.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
  sigaction(SIGCHLD, &act, NULL);
  
  if (daemon_init()) 
    {
      fprintf(stderr, "%s: Error initializing daemon\n", argv[0]);
      return -1;
    }
  
  ret = create_socket();
  
  if(ret < 0)
    {
      syslog(LOG_ERR, "couldn't create a socket!");
      exit(EXIT_FAILURE);
    }
  
  ret = read_bdb();
  
  if(ret < 0)
    {
      syslog(LOG_ERR, "Couldn't read the BerkeleyDB!");
      exit(EXIT_FAILURE);
    }
  
  mytime = time(NULL);
  
  while (1) 
    { /* Main server loop - forever */
      build_select_list();
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      if(flag_reread_bdb)
        {
          read_bdb();
          flag_reread_bdb = 0;
        }
      
      readsocks = select(high_fd+1, &socks, (fd_set *) 0, 
                         (fd_set *) 0, &timeout);

      if (readsocks < 0 && errno != EINTR) 
        {
          syslog(LOG_ERR, "select() failed");
          exit(EXIT_FAILURE);
        }
      
      if(readsocks > 0)
        read_socket();


      newtime = time(NULL);
      
      for(listnum = 0; listnum < MAXCONN; listnum++)
        {
          if(connectlist[listnum] != 0)
            {
              if(newtime > (connecttime[listnum] + 60))
                {
                  send_data("001 No data received in specified timeout, good bye.\n", &listnum);
                  close_sock(listnum);
                }
            }
        }

      if(newtime > (mytime + 5))
        {
          check_bots();
          mytime = newtime;
        }
    }
  
  return 0;
}

