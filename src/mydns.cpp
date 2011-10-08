/*
MYDNS

ABOUT:    simple DNS server
AUTHOR:   Petr Nohejl (xnohej00)
INFO:     for more informations read documentation
OS:		  GNU/Linux

RESOURCES:
http://en.wikipedia.org/wiki/Berkeley_sockets
http://www.builder.cz/art/cpp/udp1.html
http://www.gammon.com.au/pcre/pcrecpp.html
http://dce.felk.cvut.cz/pos/cv4/
http://www.netfor2.com/dns.htm
http://www.developerweb.net/forum/showthread.php?t=2933
*/


#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <string.h>
#include <pcrecpp.h>
#include <ctime>
#include <signal.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "mydns.h"


using namespace std;
using namespace pcrecpp;



/*** KONSTRUKTOR **************************************************************/
Mydns::Mydns()
{
	// inicializace
	this->confPort = 53; // implicitni cislo portu
	this->confDefaultTTL = 0;
	this->confDefaultDomain = "";
	this->confDefaultIP = "";
	this->confInterfaceAny = false;
}



/*** DESTRUKTOR ***************************************************************/
Mydns::~Mydns()
{
	
}



/*** REMOVE COMMENT ***********************************************************/
string Mydns::removeComment(string line)
{
	size_t found;
  	found = line.find_first_of(COMMENT);	
	if (found!=string::npos) line = line.substr (0, found);	
	return line;
}



/*** CUT WHITESPACES **********************************************************/
string Mydns::cutWhitespace(string line)
{
	int start;
	int end;
	
	for(start=0;start<(int) line.length();start++)
	{	
		if(line.at(start) != ' ' && line.at(start) != '\t')
			break;
	}
	
	for(end=line.length()-1;end>0;end--)
	{
		if(line.at(end) != ' ' && line.at(end) != '\t')
			break;
	}
	
	if(start<=end)
		line = line.substr (start, end-start+1);
	else
		line = "";
		
	return line;
}



/*** PARSE INTERFACE **********************************************************/
void Mydns::parseInterface(string interface)
{
	string head;
	string tail;
	
	// orezani pocatecniho slova interface	
	string patternInit = "^interface(.*)$";
	if(RE(patternInit, RE_Options().set_caseless(true)).FullMatch(interface, &tail) == 0) return;
	
	// parsovani
	string patternInterface = "^[ \\t]+([a-zA-Z0-9]+)(.*)$";
	string patternIP = "^[ \\t]+(\\d+\\.\\d+\\.\\d+\\.\\d+)(.*)$";	
	while(true)
	{
		if(RE(patternIP, RE_Options().set_caseless(true)).FullMatch(tail, &head, &tail) != 0)
		{
			this->confInterfaceIP.push_back(head);
		}
		else if(RE(patternInterface, RE_Options().set_caseless(true)).FullMatch(tail, &head, &tail) != 0)
		{
			this->confInterface.push_back(head);
		}
		else return;
	}
}



/*** PARSE ********************************************************************/
int Mydns::parseConf(char *confFileName)
{
	int err = ERR_OK;
	
	// inicializace promennych
	string interface; // retezec s interface
	string tableName;
	string tableIP;
	int tableTTL;
	int state = 0; // stav pro blok DNStable { }

	// otevreni konfiguracniho souboru
	string line;
	ifstream confFile(confFileName);
	
	// kontrola existence souboru
	if(confFile.is_open())
	{
		// prochazeni souboru po radcich
		while(!confFile.eof())
		{
			// nacteni radku, odstraneni komentaru a bilych znaku
			getline(confFile, line);
			line = this->removeComment(line);
			line = this->cutWhitespace(line);		
			
			// regularni vyrazy configu			
			string patternPort =		"^port[ \\t]+(\\d+)$";
			string patternDefaultTTL =	"^defaultttl[ \\t]+(\\d+)$";			
			string patternDefaultDomain =	"^defaultdomain[ \\t]+(([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6})$";
			string patternDefaultIP =	"^defaultip[ \\t]+(\\d+\\.\\d+\\.\\d+\\.\\d+)$";
			string patternInterfaceAny =	"^interface[ \\t]+any$";
			string patternInterface =	"^interface([ \\t]+(\\d+\\.\\d+\\.\\d+\\.\\d+|[a-zA-Z0-9]+))+$";
			
			string patternTableHead =	"^dnstable$";
			string patternTableHeadStart =	"^dnstable[ \\t]*\\{$";
			string patternTableStart =	"^\\{$";
			string patternTableEnd =	"^\\}$";
			string patternTable =	"^([a-zA-Z0-9\\.]+)[ \\t]+(\\d+\\.\\d+\\.\\d+\\.\\d+)$";
			string patternTableTTL =	"^([a-zA-Z0-9\\.]+)[ \\t]+(\\d+\\.\\d+\\.\\d+\\.\\d+)[ \\t]+(\\d+)$";
	
			// parsovani konfigurace
			if(line=="")
			{
				continue;
			}
			
			// DNS table
			/*
			state 0 - not dnstable
			state 1 - dnstable
			state 2 - dnstable {		
			*/
			else if(state == 0 && RE(patternTableHead, RE_Options().set_caseless(true)).FullMatch(line) != 0)
			{
				state = 1;
			}
			else if(state == 0 && RE(patternTableHeadStart, RE_Options().set_caseless(true)).FullMatch(line) != 0)
			{
				state = 2;
			}
			else if(state == 1 && RE(patternTableStart, RE_Options().set_caseless(true)).FullMatch(line) != 0)
			{
				state = 2;
			}
			else if(state == 2 && RE(patternTable, RE_Options().set_caseless(true)).FullMatch(line, &tableName, &tableIP) != 0)
			{
				this->confTableName.push_back(tableName);
				this->confTableIP.push_back(tableIP);
				this->confTableTTL.push_back(0);
				//cout << "|TABLE: " << line << "|" << endl;
			}
			else if(state == 2 && RE(patternTableTTL, RE_Options().set_caseless(true)).FullMatch(line, &tableName, &tableIP, &tableTTL) != 0)
			{
				this->confTableName.push_back(tableName);
				this->confTableIP.push_back(tableIP);
				this->confTableTTL.push_back(tableTTL);
				//cout << "|TABLE: " << line << "|" << endl;
			}
			else if(state == 2 && RE(patternTableEnd, RE_Options().set_caseless(true)).FullMatch(line) != 0)
			{
				state = 0;
			}
			
			// other
			else if(state == 0 && RE(patternPort, RE_Options().set_caseless(true)).FullMatch(line, &this->confPort) != 0)
			{
				//cout << "|" << line << "|" << endl;
			}
			else if(state == 0 && RE(patternDefaultTTL, RE_Options().set_caseless(true)).FullMatch(line, &this->confDefaultTTL) != 0)
			{
				//cout << "|" << line << "|" << endl;	
			}
			else if(state == 0 && RE(patternDefaultDomain, RE_Options().set_caseless(true)).FullMatch(line, &this->confDefaultDomain) != 0)
			{
				//cout << "|" << line << "|" << endl;	
			}
			else if(state == 0 && RE(patternDefaultIP, RE_Options().set_caseless(true)).FullMatch(line, &this->confDefaultIP) != 0)
			{
				//cout << "|" << line << "|" << endl;	
			}
			else if(state == 0 && RE(patternInterfaceAny, RE_Options().set_caseless(true)).FullMatch(line) != 0)
			{
				this->confInterfaceAny = true;
				//cout << "|" << line << "|" << endl;	
			}
			else if(state == 0 && RE(patternInterface, RE_Options().set_caseless(true)).FullMatch(line) != 0)
			{
				interface = line;
				this->confInterfaceAny = false;
				//cout << "|" << line << "|" << endl;
			}
			else
			{
				return ERR_CONF_PARSE;	
			}
		}
		
		// parsovani interface
		this->parseInterface(interface);
				
		// kontrolni vypis konfoguracnich promennych
		/*
		cout << "port: " << this->confPort << endl;
		cout << "ttl: " << this->confDefaultTTL << endl;
		cout << "domain: " << this->confDefaultDomain << endl;
		cout << "ip: " << this->confDefaultIP << endl;
		cout << "interface any: " << this->confInterfaceAny << endl;
		cout << "------------------------------------------------------------" << endl;
		for(unsigned i=0;i<this->confInterface.size();i++)
		{
			cout << "confInterface: " << this->confInterface.at(i) << endl;
		}
		cout << "------------------------------------------------------------" << endl;
		for(unsigned i=0;i<this->confInterfaceIP.size();i++)
		{
			cout << "confInterfaceIP: " << this->confInterfaceIP.at(i) << endl;
		}
		cout << "------------------------------------------------------------" << endl;
		for(unsigned i=0;i<this->confTableIP.size();i++)
		{
			cout << "table: " << this->confTableName.at(i) << " " << this->confTableIP.at(i) << " " << this->confTableTTL.at(i) << " " << endl;
		}
		cout << "------------------------------------------------------------" << endl;
		cout << "------------------------------------------------------------" << endl;
		*/
		
		confFile.close();
	}
	else return ERR_CONF_FILE;
	
	if(this->confPort <= 0) return ERR_CONF_PORT;
	if(this->confInterface.size() <= 0 && this->confInterfaceIP.size()<=0 && this->confInterfaceAny==false) return ERR_CONF_INTERFACE;
	if(this->confDefaultDomain == "") return ERR_CONF_DOMAIN;
	if(this->confDefaultIP == "") return ERR_CONF_IP;
	if(this->confDefaultTTL <= 0) return ERR_CONF_TTL;
	if(this->confTableIP.size() <= 0 || this->confTableName.size() <= 0 || this->confTableTTL.size() <= 0) return ERR_CONF_TABLE;

	return err;
}



/*** DNS QUERY ****************************************************************/
void Mydns::dnsCode(string domain, unsigned char *response, unsigned int *posbuf)
{
	unsigned int pos = 0;
	bool init = true;
	while(true)
	{
		// konec retezce
		if(pos >= domain.length()) break;
		
		// init
		if(init)
		{				
			//urcim delku a zapisu do bufferu
			size_t found;
			found = domain.find_first_of('.', 0);
			if(found!=string::npos)
			{
				response[*posbuf] = found;	
			}
			else
			{
				response[*posbuf] = domain.length();
			}			
			
			(*posbuf)++;
			init = false;
			continue;
		}
		
		// tecka
		if(domain.at(pos)=='.')
		{			
			//urcim delku a zapisu do bufferu
			size_t found;
			found = domain.find_first_of('.', pos+1);
			if(found!=string::npos)
			{
				response[*posbuf] = found - pos - 1;	
			}
			else
			{
				response[*posbuf] = domain.length() - pos - 1;
			}	
		}
		
		// normalni znak
		else
		{
			response[*posbuf] = domain.at(pos);
		}
			pos++;
		(*posbuf)++;
	}	
	
	response[(*posbuf)++] = 0;
}



/*** DNS QUERY ****************************************************************/
int Mydns::dnsQuery(unsigned char *request, unsigned char *response, int requestSize, int *responseSize, int *queryType, string *requestStr)
{
	// kontrola velikosti dotazu
	if(requestSize<STARTMSG) return DNS_NORESPONSE;
	
	
	// pomocne promenne
	int err = DNS_OK;
	string domain = "";
	string domainConvert = "";
	string ip1;
	string ip2;
	string ip3;
	string ip4;
	unsigned int posbuf = STARTMSG;
	int anscnt = 0;
	
	unsigned char responseTc = 0;
	unsigned char responseFlags1 = 0;
	unsigned char responseFlags2 = 0;
	
	unsigned char requestId1 = request[0];
	unsigned char requestId2 = request[1];
	unsigned char requestFlags1 = request[2];
	unsigned char requestFlags2 = request[3];
	unsigned char requestQdcount1 = request[4];
	unsigned char requestQdcount2 = request[5];
	unsigned char requestAncount1 = request[6];
	unsigned char requestAncount2 = request[7];
	unsigned char requestNscount1 = request[8];
	unsigned char requestNscount2 = request[9];
	unsigned char requestArcount1 = request[10];
	unsigned char requestArcount2 = request[11];
	
	unsigned char requestQr = requestFlags1 & 128; 		// 1. bit zleva
	unsigned char requestOpcode = requestFlags1 & 120;	// 2-5. bit zleva
	//unsigned char requestAa = requestFlags1 & 4; 		// 6. bit zleva
	unsigned char requestTc = requestFlags1 & 2; 		// 7. bit zleva
	unsigned char requestRd = requestFlags1 & 1; 		// 8. bit zleva
	
	//unsigned char requestRa = requestFlags2 & 128; 		// 1. bit zleva
	//unsigned char requestZ = requestFlags2 & 112; 		// 2-4. bit zleva
	unsigned char requestRcode = requestFlags2 & 15; 		// 5-8. bit zleva
	
	unsigned char requestType;
	unsigned char requestClass;


	// osetreni chyb
	if(requestQdcount2!=1 && requestQdcount1!=0 && requestAncount2!=0 && requestAncount1!=0 && requestNscount2!=0 && requestNscount1!=0 && requestArcount2!=0 && requestArcount1!=0)
		err = DNS_NOT_IMP; // pocet dotazu
	if(requestOpcode!=0) err = DNS_NOT_IMP;		// typ dotazu
	if(requestTc!=0) err = DNS_FAIL;		// zkracena zprava
	if(requestRcode!=0) err = DNS_FAIL;		// vysledek
	if(requestQr!=0) err = DNS_FAIL;	 	// dotaz nebo odpoved
	
	
	// cteni zpravy
	if(err==DNS_OK)
	{
		// ziskani domeny
		try
		{
			int pos = STARTMSG;
			int len = request[pos];
			
			while(true)
			{
				pos++;
				for(int i=0;i<len;i++)
				{
					domain.append(1, request[pos+i]);
				}
				pos+=len;
				len = request[pos];
				if(len!=0)
				{
					domain.append(".");
					continue;
				}
				else break;
			}
		
			// typ a trida
			requestType = request[pos+=2];
			requestClass = request[pos+=2];
			
			// osetreni chyb
			if(requestType!=A && requestType!=PTR) err = DNS_NOT_IMP; // typ dotazu	
			if(requestClass!=1) err = DNS_NOT_IMP; // trida dotazu
		
			*requestStr = domain;
		
			/*
			cout << "domena: " << domain << endl;
			cout << "requestType: " << (int) requestType << endl;
			cout << "requestClass: " << (int) requestClass << endl;
			*/
		}
		catch(...)
		{
			err = DNS_ERR;
		}
	}
	
	
	// zpracovani zpravy
	if(err==DNS_OK)
	{
		string search;
		int ttl;
		
		// query
		dnsCode(domain, response, &posbuf);
		response[posbuf++] = 0;
		response[posbuf++] = requestType;
		response[posbuf++] = 0;
		response[posbuf++] = requestClass;
		
		// A zaznam
		if(requestType==A)
		{
			// uprava IP z klasickeho tvaru na tvar arpa net: 1.0.0.127.in-addr.arpa
			string patternIP = "^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)$";
			bool nodomain = true;
			
			// vyhledej v databazi IP ze zadane domeny
			for(unsigned i=0;i<this->confTableName.size();i++)
			{
				if(this->confTableName.at(i) == domain) 
				{
					search = this->confTableIP.at(i);
					ttl = this->confTableTTL.at(i);
					
					if(ttl==0) ttl = this->confDefaultTTL;
					
					if(RE(patternIP, RE_Options().set_caseless(true)).FullMatch(search, &ip1, &ip2, &ip3, &ip4) != 0)
					{
						//search = ip4 + "." + ip3 + "." + ip2 + "." + ip1 + ".in-addr.arpa";
						//cout << "ip's converted: " << search << endl;
					}

					//answer
					response[posbuf++] = 192;
					response[posbuf++] = STARTMSG;
					response[posbuf++] = 0;
					response[posbuf++] = requestType;
					response[posbuf++] = 0;
					response[posbuf++] = requestClass;
					response[posbuf++] = ttl >> 24;
					response[posbuf++] = ttl >> 16;
					response[posbuf++] = ttl >> 8;
					response[posbuf++] = ttl;
			
					response[posbuf++] = 0;
					response[posbuf++] = 4;
					response[posbuf++] = atoi(ip1.c_str());
					response[posbuf++] = atoi(ip2.c_str());
					response[posbuf++] = atoi(ip3.c_str());
					response[posbuf++] = atoi(ip4.c_str());
					
					anscnt++;
					nodomain = false;	
				}
				
				if(posbuf>=LIMITSIZE-1) break;
			}
			
			if(nodomain)
			{
				search = this->confDefaultIP;
				ttl = this->confDefaultTTL;
				
				if(RE(patternIP, RE_Options().set_caseless(true)).FullMatch(search, &ip1, &ip2, &ip3, &ip4) != 0)
				{
					//search = ip4 + "." + ip3 + "." + ip2 + "." + ip1 + ".in-addr.arpa";
					//cout << "ip's converted: " << search << endl;
				}
		
				//answer
				response[posbuf++] = 192;
				response[posbuf++] = STARTMSG;
				response[posbuf++] = 0;
				response[posbuf++] = requestType;
				response[posbuf++] = 0;
				response[posbuf++] = requestClass;
				response[posbuf++] = ttl >> 24;
				response[posbuf++] = ttl >> 16;
				response[posbuf++] = ttl >> 8;
				response[posbuf++] = ttl;
			
				response[posbuf++] = 0;
				response[posbuf++] = 4;
				response[posbuf++] = atoi(ip1.c_str());
				response[posbuf++] = atoi(ip2.c_str());
				response[posbuf++] = atoi(ip3.c_str());
				response[posbuf++] = atoi(ip4.c_str());
				
				anscnt++;
			}	
		}
		
		// PTR zaznam
		else if(requestType==PTR)
		{
			search = this->confDefaultDomain;
			ttl = this->confDefaultTTL;
			
			// uprava IP na klasicky tvar z tvaru arpa net: 1.0.0.127.in-addr.arpa
			string patternArpa = "^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)\\.in-addr\\.arpa$";

			if(RE(patternArpa, RE_Options().set_caseless(true)).FullMatch(domain, &ip4, &ip3, &ip2, &ip1) != 0)
			{
				domainConvert = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
				//cout << "domainConvert: " << domainConvert << endl;
			}

			// vyhledej v databazi Nazev ze zadane IP
			for(unsigned i=0;i<this->confTableIP.size();i++)
			{
				if(this->confTableIP.at(i) == domainConvert) 
				{
					search = this->confTableName.at(i);
					ttl = this->confTableTTL.at(i);
					if(ttl==0) ttl = this->confDefaultTTL;
					break;
				}
			}
		
			//answer
			response[posbuf++] = 192;
			response[posbuf++] = STARTMSG;
			response[posbuf++] = 0;
			response[posbuf++] = requestType;
			response[posbuf++] = 0;
			response[posbuf++] = requestClass;
			response[posbuf++] = ttl >> 24;
			response[posbuf++] = ttl >> 16;
			response[posbuf++] = ttl >> 8;
			response[posbuf++] = ttl;
			
			response[posbuf++] = (search.length()+2) >> 8;
			response[posbuf++] = (search.length()+2);
			dnsCode(search, response, &posbuf);
			
			anscnt++;
		}
	}

	
	// nastaveni flags
	if(posbuf>=LIMITSIZE-1) 
	{
		responseTc = 1; // zprava je vetsi jak 512 byte	
		posbuf = LIMITSIZE;
	}
	responseFlags1 = responseFlags1 | (1 << 7);
	responseFlags1 = responseFlags1 | (requestOpcode << 3);
	responseFlags1 = responseFlags1 | (0 << 2);
	responseFlags1 = responseFlags1 | (responseTc << 1);
	responseFlags1 = responseFlags1 | (requestRd << 0);
	responseFlags2 = responseFlags2 | (0 << 7);
	responseFlags2 = responseFlags2 | (0 << 4);
	responseFlags2 = responseFlags2 | (err << 0);
	
	
	// odpoved
	switch(err)
	{
		case DNS_OK:
			*responseSize = posbuf;

			// identifikator zpravy
			response[0] = requestId1;
			response[1] = requestId2;
			
			// flags		
			response[2] = responseFlags1;
			response[3] = responseFlags2;
					
			// QDCOUNT
			response[4] = 0;
			response[5] = 1;
	
			// ANCOUNT
			response[6] = 0;
			response[7] = anscnt;
	
			// NSCOUNT
			response[8] = 0;
			response[9] = 0;
					
			// ARCOUNT
			response[10] = 0;
			response[11] = 0;			
			break;
			
		case DNS_ERR:
		case DNS_FAIL:
		case DNS_NOT_IMP:
			*responseSize = STARTMSG;

			// identifikator zpravy
			response[0] = requestId1;
			response[1] = requestId2;
			
			// flags		
			response[2] = responseFlags1;
			response[3] = responseFlags2;
					
			// QDCOUNT
			response[4] = 0;
			response[5] = 0;
	
			// ANCOUNT
			response[6] = 0;
			response[7] = 0;
	
			// NSCOUNT
			response[8] = 0;
			response[9] = 0;
					
			// ARCOUNT
			response[10] = 0;
			response[11] = 0;
			break;
			
		case DNS_NORESPONSE:
		default:
			*responseSize = 0;
			break;
			
	}

	*queryType = requestType;
	return err;
}



/*** SOCKETS ******************************************************************/
int Mydns::createSockets()
{
	struct ifaddrs *ifs, *ifa;
	getifaddrs(&ifs);
	int sock;
	struct sockaddr_in sockParam;
	
	if(this->confInterfaceAny)
	{
		// vytvoreni noveho soketu
           	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) return ERR_SOCKET;
           	
           	// parametry soketu
      		sockParam.sin_family = AF_INET; // rodina protokolu
           	sockParam.sin_port = htons(this->confPort); // port
           	sockParam.sin_addr.s_addr = INADDR_ANY; // IP
   				
           	// inicializace soketu
           	if (bind(sock, (sockaddr *)&sockParam, sizeof(sockParam)) == -1) return ERR_SOCKET_BIND;
		this->sockets.push_back(sock);
	}
	else
	{
		// kontroluje rozhrani v pocitaci
		for (ifa=ifs; ifa!=NULL; ifa=ifa->ifa_next)
		{
			if (ifa->ifa_addr->sa_family == AF_INET)
			{
				// kontroluje rozhrani z konfiguracniho souboru
				for (unsigned int i=0; i<this->confInterface.size(); i++)
				{
         					if (strcmp(ifa->ifa_name, this->confInterface.at(i).c_str()) == 0)
         					{
           					// vytvoreni noveho soketu
           					if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) return ERR_SOCKET;		

						// parametry soketu
           					sockParam.sin_family = AF_INET; // rodina protokolu
           					sockParam.sin_port = htons(this->confPort); // port
           					sockParam.sin_addr.s_addr = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr)->sin_addr.s_addr; // interface
           				
           					// inicializace soketu
           					if (bind(sock, (sockaddr *)&sockParam, sizeof(sockParam)) == -1) return ERR_SOCKET_BIND;
           					this->sockets.push_back(sock);
         					}
      				}
    			}
  		}
  		
  		// kontroluje IP z konfiguracniho souboru
		for (unsigned int i=0; i<this->confInterfaceIP.size(); i++)
		{
			// vytvoreni noveho soketu
           		if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) return ERR_SOCKET;		

			// parametry soketu
           		sockParam.sin_family = AF_INET; // rodina protokolu
           		sockParam.sin_port = htons(this->confPort); // port
           		sockParam.sin_addr.s_addr = inet_addr(this->confInterfaceIP.at(i).c_str()); // IP
           				
           		// inicializace soketu
           		if (bind(sock, (sockaddr *)&sockParam, sizeof(sockParam)) == -1) return ERR_SOCKET_BIND;
           		this->sockets.push_back(sock);
		}	
  	}

	return ERR_OK;
}



/*** DNS **********************************************************************/
int Mydns::dns(char *confFileName)
{
	int err = ERR_OK;
	
	// parsovani konfiguracniho souboru
	err = this->parseConf(confFileName);
	if(err != ERR_OK) return err;
	
	// vytvoreni soketu z rozhrani
	err = this->createSockets();
	if(err != ERR_OK) return err;
	if(this->sockets.size() <= 0) return ERR_NO_SOCKET;
	
	// vynulovani mnoziny sledovanych deskriptoru soketu a pridani novych
	fd_set readset; // definice mnoziny sledovanych deskriptoru - soketu
	int highest = 0;
	FD_ZERO(&readset);
	for(unsigned i=0; i<this->sockets.size(); i++)
	{
		FD_SET(this->sockets.at(i), &readset);
		if(this->sockets.at(i)>highest) highest = this->sockets.at(i);
		//cout << "SOCKET #" << this->sockets.at(i) << endl;	
	}

	// pomocne promenne serveru
   	sockaddr_in clientInfo;	// info o pripojenem klientovi
   	unsigned char buf[BUFSIZE];	// prijimaci buffer - pomoci %x v printfu zobrazim binarni data
   	int size;			// pocet prijatych a odeslanych byte
    	socklen_t addrlen;		// velikost adresy vzdaleneho PC
   	int count = 0;		// pocet odeslanych pozadavku
    	pid_t pid;			// id procesu
    	int resultDns;		// vysledek zpracovani zpravy
	int resultSelect;		// vysledek selectu
	struct timeval tv; 		// timeout
	tv.tv_sec = 0;		// timeout nastaven na 1 sekundu
	tv.tv_usec = 1000;		// timeout nastaven na 1 sekundu


	// hlavni cyklus serveru
	while(true)
	{
		// multiplexing
		resultSelect = select(highest + 1, &readset, NULL, NULL, NULL);

		if(resultSelect < 0) ; // error //return ERR_SELECT;
		else if(resultSelect == 0) ; // timeout
		else if(resultSelect > 0)
		{	
			// kontroluje vsechny sokety (rozhrani)
			for(unsigned j=0; j<this->sockets.size(); j++)
			{
				// soket je pripraven
				if(FD_ISSET(this->sockets.at(j), &readset))
				{
					// predejiti vzniku zombie
					struct sigaction sa;
					sa.sa_handler = SIG_IGN;
					sa.sa_flags = 0;
					sigemptyset(&sa.sa_mask);
					if (sigaction(SIGCHLD, &sa, NULL) == -1)
					{
						cerr << "Error: cannot kill zombie!\n";
					}
				
					// odposlouchavani zpravy
					addrlen = sizeof(clientInfo);
					if ((size = recvfrom(this->sockets.at(j), buf, BUFSIZE - 1, 0, (sockaddr *)&clientInfo, &addrlen)) == -1) 
					{
						cerr << "Error: cannot receive data!\n"; //return ERR_RECV;
						continue;
					}
					else
					{
						// novy proces
						pid = fork();
		
						// parent
						if (pid > 0) 
						{
							// empty
						}
				
						// child
						else if (pid == 0)
						{								
							// zjistime IP klienta
							//cout << "Prisel pozadavek z adresy: " << inet_ntoa((in_addr)clientInfo.sin_addr) << endl;
			
							// kontrolni vypis
							buf[size] = '\0';
							/*
							cout << "Prijato: " << size << " bytu" << endl;
							for(int i=0;i<size;i++) printf("%x ", buf[i]);
							cout << endl;
							*/
							
							// odpoved
							try
							{
								unsigned char response[BUFSIZE];
								int responseSize = 0;
								int queryType = 0;
								string requestStr = "";
								resultDns = dnsQuery(buf, response, size, &responseSize, &queryType, &requestStr);

								// odpoved
								if(responseSize>0)
								{
									if (sendto(this->sockets.at(j), response, responseSize, 0, (sockaddr *)&clientInfo, addrlen) == -1) cerr << "Error: cannot send data!\n"; //return ERR_SEND;
									//cout << "Odeslano: " << responseSize << " bytu" << endl;
																		
									// log
									time_t rawtime;
									struct tm * timeinfo;
									char buffer [80];
									time(&rawtime);
									timeinfo = localtime(&rawtime);
									strftime(buffer, 80, "%c", timeinfo);
									
									string q="";
									if(queryType == A) q="A";
									else if(queryType == PTR) q="PTR";
									
									// zapis do souboru
									try
									{
										ofstream file; // vystupni proud do souboru (zapis)
   										file.open(LOGFILE, ios::out | fstream::app);
   										if(file.is_open())
   										{
   											file << "[" << buffer << "] " << inet_ntoa((in_addr)clientInfo.sin_addr) << " requested for " << q << " record " << requestStr << ", rcvd: " << size << ", sent: " << responseSize << endl;
   											file.close();
   										}
									}
									catch(...)
									{
										
									}
								}
						
								// kontrolni vypis
								/*
								for(int i=0;i<responseSize;i++) printf("%x ", response[i]);
								cout << endl;
								cout << "------------------------------------------------------------" << endl;
								cout << "------------------------------------------------------------" << endl;
								*/
							}
							catch(...)
							{
								cerr << "Error: cannot send data!\n";
							}	
					
							// ukonceni procesu
							exit(0);
						}
						else cerr << "Error: cannot fork process!\n"; //return ERR_FORK;
					}
					
					count++;	
				}
			}
		}
	}
	
	// uvolneni soketu
	for(unsigned i=0; i<this->sockets.size(); i++)
	{
		close(this->sockets.at(i));	
	}
	
	return err;
}



/*** HELP *********************************************************************/
int Mydns::help()
{
	cout << "DNS server" << endl;
	cout << "Copyright (c)2010 Petr Nohejl (xnohej00)" << endl << endl;
	cout << "Mydns is simple DNS server for GNU/Linux. It supports A and PTR standard queries." << endl;
	cout << "Server is configurated in configure file. All accesses are logged into the log file '" << LOGFILE << "'." << endl;
	cout << "Read documentation for more informations about server and usage." << endl << endl;
	cout << "Usage: mydns -f configure_file" << endl;
	cout << "       mydns -h" << endl;
	
	return ERR_OK;
}



/*** MAIN *********************************************************************/
int main(int argc, char *argv[])
{	
	int err = ERR_OK;
	Mydns *dns;
	dns = new Mydns();
	
	// zpracovani argumentu programu
	if(argc==2)
	{
		// napoveda
		if(strcmp(argv[1], "-h") == 0) err = dns->help();
		else err = ERR_ARG;
	}
	else if(argc==3)
	{
		
		// spusteni dns serveru
		if(strcmp(argv[1], "-f") == 0) 
		{						
			err = dns->dns(argv[2]);				
		}
		else err = ERR_ARG;		
	}
	else err = ERR_ARG;		
	
	// kontrola chyb
	if(err>ERR_OK)
	{
		switch (err)
		{
			case ERR_ARG:
				cerr << "Error: invalid arguments! Run './mydns -h' for help.\n";
				break;
			case ERR_CONF_FILE:
				cerr << "Error: configuration file '" << argv[2] << "' doesn't exist!\n";
				break;
			case ERR_CONF_PARSE:
				cerr << "Error: parse error in configuration file '" << argv[2] << "'!\n";
				break;
			case ERR_CONF_VALUE_INVALID:
				cerr << "Error: invalid value in configuration file '" << argv[2] << "'!\n";
				break;
			case ERR_CONF_PORT:
				cerr << "Error: invalid value of port or no port set in configuration file '" << argv[2] << "'! Please set correct port.\n";
				break;
			case ERR_CONF_INTERFACE:
				cerr << "Error: missing interfaces in configuration file '" << argv[2] << "'! Please set correct interfaces.\n";
				break;
			case ERR_CONF_DOMAIN:
				cerr << "Error: missing default domain in configuration file '" << argv[2] << "'! Please set correct default domain.\n";
				break;
			case ERR_CONF_IP:
				cerr << "Error: missing default IP in configuration file '" << argv[2] << "'! Please set correct default IP.\n";
				break;
			case ERR_CONF_TTL:
				cerr << "Error: invalid value of default TTL or no TTL set in configuration file '" << argv[2] << "'! Please set correct TTL.\n";
				break;
			case ERR_CONF_TABLE:
				cerr << "Error: missing DNS table in configuration file '" << argv[2] << "'! Please set correct DNS table.\n";
				break;		
			case ERR_SOCKET:
				cerr << "Error: cannot create socket!\n";
				break;
			case ERR_SOCKET_BIND:
				cerr << "Error: cannot bind socket!\n";
				break;
			case ERR_NO_SOCKET:
				cerr << "Error: no socket is available!\n";
				break;		
			case ERR_RECV:
				cerr << "Error: cannot receive data!\n";
				break;
			case ERR_SEND:
				cerr << "Error: cannot send data!\n";
				break;
			case ERR_FORK:
				cerr << "Error: cannot fork process!\n";
				break;
			case ERR_SELECT:
				cerr << "Error: multiplexing fault!\n";
				break;
			default:
				cerr << "Error: unknown error!\n";
				break;
		}
		
		delete dns;
		return -1;
	}

	delete dns;
	return 0;
}
