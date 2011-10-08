#ifndef __MYDNS_H__
#define __MYDNS_H__

#define COMMENT '#'
#define BUFSIZE 2048
#define LIMITSIZE 512
#define STARTMSG 12
#define PTR 12
#define A 1
#define LOGFILE "accesslog"

using namespace std;
using namespace pcrecpp;

enum Errors { ERR_OK, ERR_ARG, ERR_CONF_FILE, ERR_CONF_PARSE, ERR_CONF_VALUE_INVALID, ERR_CONF_PORT, ERR_CONF_INTERFACE, ERR_CONF_DOMAIN, ERR_CONF_IP, ERR_CONF_TTL, ERR_CONF_TABLE, ERR_SOCKET, ERR_SOCKET_BIND, ERR_NO_SOCKET, ERR_RECV, ERR_SEND, ERR_FORK, ERR_SELECT };
enum Dns { DNS_OK, DNS_ERR, DNS_FAIL, DNS_NOT_EXIST, DNS_NOT_IMP, DNS_REFUSED, DNS_NORESPONSE };

class Mydns
{
	private:
		int confPort;
		int confDefaultTTL;
		string confDefaultIP;
		string confDefaultDomain;
		bool confInterfaceAny;	
		vector<string> confInterface;
		vector<string> confInterfaceIP;
		vector<string> confTableName;
		vector<string> confTableIP;
		vector<int> confTableTTL;
		vector<int> sockets;
				
		int parseConf(char *confFileName);
		void parseInterface(string interface);
		string cutWhitespace(string line);
		string removeComment(string line);
		int createSockets();
		int dnsQuery(unsigned char *request, unsigned char *response, int requestSize, int *responseSize, int *queryType, string *requestStr);
		void dnsCode(string domain, unsigned char *response, unsigned int *posbuf);
		
	
	
	public:	
		int help();
		int dns(char *confFileName);
		Mydns();
		~Mydns();
		
};

#endif