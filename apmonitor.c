#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>


#include <mosquitto.h>

#define HOSTAPD_SOCKETS "/var/run/hostapd/"
#define BUF_SIZE 1024

int fd;
static struct sigaction sa_int;
static int sigint_c=0;
char buf[BUF_SIZE];
char cpath[PATH_MAX];
char spath[PATH_MAX];

char *interface;

static struct mosquitto *mqtt = NULL;
char *mqtt_host=NULL;
char *mqtt_clientid=NULL;
char *mqtt_topic_prefix=NULL;

#define SETSIG(sa, sig, fun, flags) \
	do { \
		sa.sa_handler = fun; \
		sa.sa_flags = flags; \
		sigemptyset(&sa.sa_mask); \
		sigaction(sig, &sa, NULL); \
	} while(0)

int parse(char *response);

static void sig_handler_sigint(int i)
{
sigint_c++;
fprintf(stderr, "SIGINT\n");
}

static void mqtt_log_callback(struct mosquitto *m, void *userdata, int level, const char *str)
{
fprintf(stderr, "[MQTT-%d] %s\n", level, str);
}

static void mqtt_pub_callback(struct mosquitto *m, void *userdata, int mid)
{
fprintf(stderr, "[MQTT-%d]\n", mid);
}

int mqtt_publish_info_topic_int(const char *topic, int value)
{
int r;
char ftopic[80];
char data[16];

snprintf(ftopic, sizeof(ftopic), "%s/%s/%s", mqtt_topic_prefix, interface, topic);
snprintf(data, sizeof(data), "%d", value);

printf("PUB: [%s] = [%s] %d\n", ftopic, data, strlen(data));

r=mosquitto_publish(mqtt, NULL, ftopic, strlen(data), data, 1, false);
if (r!=MOSQ_ERR_SUCCESS)
	fprintf(stderr, "MQTT Publish for info [%s] failed with %s\n", topic, mosquitto_strerror(r));

return r;
}

int getreply(char *buf, size_t s)
{
int r;

r=recv(fd, buf, s, 0);
if (r>0) {
	buf[r]=0;
	parse(buf);
}
if (r<0)
	perror("recv");

return r;
}

int sendcmd(char *cmd, size_t len)
{
int r;

r=send(fd, cmd, len, 0);
if (r<0)
	perror("send");

return r;
}

int parse(char *response)
{
int r=-1;
char mac[17];

printf("R: [%s] %d\n", response, strlen(response));

if (strncmp(response, "OK\n", 3)==0)
	return 0;
if (strncmp(response, "PONG\n", 5)==0)
	return 0;
// AP-STA-DISCONNECTED
// AP-STA-CONNECTED
// <?>INFO MAC

if (response[0]=='<' && strchr(response,'>')!=NULL) {
	char *p;

	p=strchr(response, '>');

	if (strncmp(p+1, "AP-STA-CONNECTED", 16)==0)
		r=1;
	else if (strncmp(p+1, "AP-STA-DISCONNECTED", 19)==0)
		r=2;
	else
		return -1;

	p=strchr(p, ' ');

	// Copy MAC
	strncpy(mac, p+1, 17);
	mac[17]=0;

//	printf("%d: %s\n", r, mac);

	mqtt_publish_info_topic_int(mac, r==2 ? 0 : 1);
}

return -1;
}

int connect2hostapd(char *interface)
{
struct sockaddr_un addr;
struct sockaddr_un laddr;
int r,fd=-1;

fd=socket(PF_UNIX, SOCK_DGRAM, 0);
if (fd<0)
	goto error;

// XXX use mkdtemp()
r=snprintf(cpath, sizeof(cpath), "/tmp/monitor-%s-%d", interface, getpid());
if (r<0)
	goto error;

memset(&laddr, 0, sizeof(struct sockaddr_un));
laddr.sun_family = AF_UNIX;
strncpy(laddr.sun_path, cpath, sizeof(laddr.sun_path)-1);

r=bind(fd, (struct sockaddr *) &laddr, sizeof(struct sockaddr_un));
if (r<0)
	goto error;

r=snprintf(spath, sizeof(spath), "%s%s", HOSTAPD_SOCKETS, interface);
if (r<0)
	goto error;

memset(&addr, 0, sizeof(struct sockaddr_un));
addr.sun_family = AF_UNIX;
strncpy(addr.sun_path, spath, sizeof(addr.sun_path)-1);

r=connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
if (r<0)
	goto error;

return fd;

error:;
	perror("connect2hostapd");
	if (fd>0)
		close(fd);

return r;
}

void main_loop_mqtt()
{
fd_set rfds;
fd_set wfds;
int port = 1883;
int keepalive = 120;
bool clean_session = true;
int mfd;
struct timeval tv;

printf("MQTT Mode: Host: '%s' ID: '%s' Tprefix: '%s'\n", mqtt_host, mqtt_clientid, mqtt_topic_prefix);

mqtt=mosquitto_new(mqtt_clientid, clean_session, NULL);

mosquitto_log_callback_set(mqtt, mqtt_log_callback);
mosquitto_publish_callback_set(mqtt, mqtt_pub_callback);

if (mosquitto_connect(mqtt, mqtt_host, port, keepalive)) {
	fprintf(stderr, "Unable to connect.\n");
	goto mqtt_out;
}

printf("MQTT Connected, monitoring AP for stations now\n");
mfd=mosquitto_socket(mqtt);
if (mfd<0)
	fprintf(stderr, "Failed to get mosquitto socket!\n");

while (sigint_c==0) {
	FD_ZERO(&rfds);
	FD_SET(mfd, &rfds);
	FD_SET(fd, &rfds);

	FD_ZERO(&wfds);
	FD_SET(mfd, &wfds);

	tv.tv_sec = 15;
	tv.tv_usec = 0;

	fprintf(stderr, "S\n");
	int r=select(mfd+1, &rfds, NULL /* &wfds */, NULL, &tv);
	if (r<0) {
		perror("select");
		continue;
	}

	fprintf(stderr, "s\n");

	if (FD_ISSET(fd, &rfds)) {
		fprintf(stderr, "h\n");
		getreply(buf, BUF_SIZE);
	}
	if (FD_ISSET(mfd, &rfds)) {
		fprintf(stderr, "mr\n");
		mosquitto_loop_read(mqtt, 1);
	}
//	if (FD_ISSET(mfd, &rfds) && mosquitto_want_write(mqtt)) {
	if (mosquitto_want_write(mqtt)) {
		fprintf(stderr, "mw\n");
		mosquitto_loop_write(mqtt, 1);
	}

//	sendcmd("PING", 4);
	mosquitto_loop_misc(mqtt);

	printf(".\n");
}

mqtt_out:;

mosquitto_destroy(mqtt);
}

int main(int argc, char **argv)
{
int r, opt;

// Default interface
interface="wlan0";

//Default MQTT settings
mqtt_host="localhost";
mqtt_topic_prefix="ap"; // /ap/<interface>/<MAC>/0,1
mqtt_clientid="ap-monitor";

while ((opt = getopt(argc, argv, "t:h:c:i:")) != -1) {
	switch (opt) {
	case 'h':
	mqtt_host=optarg;
	break;
	case 't':
	mqtt_topic_prefix=optarg;
	break;
	case 'c':
	mqtt_clientid=optarg;
	break;
	case 'i':
	interface=optarg;
	break;
	default:
	fprintf(stderr, "Usage: %s\n\n", argv[0]);
	fprintf(stderr, " -h 		MQTT host\n");
	fprintf(stderr, " -t 		MQTT topic prefix\n");
	fprintf(stderr, " -c 		MQTT client id\n");
	fprintf(stderr, " -i 		WLAN interface (default: wlan0))\n");
	return 255;
	break;
	}
}

fd=connect2hostapd(interface);
if (fd<0)
	return 1;

SETSIG(sa_int, SIGINT, sig_handler_sigint, 0); // Not SA_RESTART !

mosquitto_lib_init();

sendcmd("ATTACH", 6);
sendcmd("PING", 4);

main_loop_mqtt();

sendcmd("DETACH", 6);

unlink(cpath);

mosquitto_lib_cleanup();

return 0;
}
