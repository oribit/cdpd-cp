/* Checkpoint CDP / LLDP speaker 
 *
 * Author: Alvaro Caso (alvaroc@ixeya.com)
 * Version: 1.0
 * 
 * based in the work of Alexandre Snarskii (http://snar.spb.ru/prog/cdpd/)
 *
 * This program allow linux systems (specially designed for Checkpoint Firewalls) to speak/understand CDP/LDDP. It will send a CDP/LLDP packet and will listen for this packet during a configurable period of time.
 * In case CDP and LLDP are choosen, the first packet to arrive it will be used to get the information.
 *
 * The output is formatted in a easy way to parse in case it wanted to be used in a script.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <sys/sysctl.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

extern char* optarg;

#define MAX_IFS 128

#define CDP_CAP_ROUTER 0x01
#define CDP_CAP_TBRIDG 0x02
#define CDP_CAP_SBRIDG 0x04
#define CDP_CAP_SWITCH 0x08
#define CDP_CAP_HOST   0x10


#define SIZE_ETHERNET 14
#define SIZE_LLC_HEADER 8

#define CDP_DEVICEID    0x01
#define CDP_ADDRESS     0x02
#define CDP_PORTID      0x03
#define CDP_CAPS        0x04
#define CDP_VER         0x05
#define CDP_PLAT        0x06
#define CDP_IPNETPRE    0x07
#define CDP_HELLO       0x08
#define CDP_VTPDOMAIN   0x09
#define CDP_NATIVEVLAN  0x0A
#define CDP_DUPLEX      0x0B
#define CDP_TLV_VLREPLY 0x0E
#define CDP_TLV_VLQUERY 0x0F
#define CDP_TLV_POWER   0x10
#define CDP_MTU         0x11
#define CDP_SYSTEM_NAME 0x14
#define CDP_SYSTEM_OID  0x15
#define CDP_MGMT_ADDR   0x16
#define CDP_LOCATION    0x17

#define CDP_ADDR_NLPID  0x01
#define CDP_ADDR_8022   0x02

#define CDP_ADDR_PROTO_IPV4     0xCC
#define CDP_ADDR_PROTO_IPV6     0xAAAA030000000800

// #define LLDP_TYPE 0x88cc
#define LLDP_TYPE 0xcc88

#define LLDP_END        0x00
#define LLDP_CHASSISID  0x01
#define LDDP_PORTID     0x02
#define LLDP_TTL        0x03
#define LLDP_PORTDESC   0x04
#define LLDP_SYSNAME    0x05
#define LLDP_SYSDESC    0x06
#define LLDP_SYSCAP     0x07
#define LLDP_MGMTADDR   0x08
#define LLDP_ORG        0x7F
#define LLDP_IEEE8021   0x0080c2
#define LLDP_VLANID     0x01

//LLDP Chasis ID SUBTYPE
#define LLDPCHID_CHASSISCOM     0x01
#define LLDPCHID_INTALIAS       0x02
#define LLDPCHID_PORT           0x03
#define LLDPCHID_MAC            0x04
#define LDDPCHID_NETWORK        0x05
#define LDDPCHID_IFACENAME      0x06
#define LDDPCHID_LOCALLY        0x07

//LLDP Port ID SUBTYPE
#define LDDPPOID_INTALIAS       0x01
#define LDDPPOID_PORTCOM        0x02
#define LDDPPOID_MAC            0x03
#define LDDPPOID_NET            0x04
#define LDDPPOID_IFACENAME      0x05
#define LDDPPOID_CIRCUITID      0x06
#define LDDPPOID_LOCALLY        0x07

#define ADDR_FAMILY_IPV4        0x01
#define ADDR_FAMILY_IPV6        0x02

#define SNAP_LEN 8192
#define MAX_NUM_PACKET_CAP 50

struct s_myNeighbor
{
	char localIF[255];
	unsigned char localMAC[6];
        char Chassis[512];
        char Port[255];
        char PortDesc[255];
        char SysName[512];
        char SysDesc[512];
        char ManagementIP[255];
        char VLAN[255];
	struct s_myNeighbor* next;
};

struct __attribute__ ((__packed__)) cdp_header { 
/* ethernet 802.3 header */
	unsigned char dst_addr[6];
	unsigned char src_addr[6];
	u_int16_t length;
/* LLC */
	u_int8_t dsap;
	u_int8_t ssap;
/* llc control */
	u_int8_t control;
	u_int8_t orgcode[3];
	u_int16_t protocolId;
};

struct cdp_interface {
        struct cdp_interface* next;
        char* name;
        struct sockaddr_in address;
#ifdef AF_INET6
        struct sockaddr_in6 ipv6address;
#endif
        unsigned char eaddr[6];
        pcap_t* pcap;
        char errbuf[PCAP_ERRBUF_SIZE];
};

static struct utsname myuname;
static char mysysname[512];
static int debug=0;
static unsigned char capabilities[4]={0x00,0x10,0x00,0x00};

pcap_t* capturehandle=NULL; // global to use ALARM

int sx_write_long(unsigned char* buffer, u_int32_t data)
{ 
#if WORDS_BIGENDIAN
	buffer[0]=(data>>24)&0xff;
	buffer[1]=(data>>16)&0xff;
	buffer[2]=(data>>8)&0xff;
	buffer[3]=data&0xff;
#else 
	buffer[3]=(data>>24)&0xff;
	buffer[2]=(data>>16)&0xff;
	buffer[1]=(data>>8)&0xff;
	buffer[0]=data&0xff;
#endif
	return 1;
};

struct s_myNeighbor* addNeighbor(struct s_myNeighbor** head, char* localIF, unsigned char* mac)
{
        struct s_myNeighbor* myNeighbor = malloc(sizeof(struct s_myNeighbor));

        if (myNeighbor != NULL) {
		memset(myNeighbor,0,sizeof(struct s_myNeighbor));
		strncpy(myNeighbor->SysName, "<sleeping>\x00", 11);

/*                strncpy(myNeighbor->localMAC, mac, sizeof(myNeighbor->localMAC));
                strncpy(myNeighbor->SysName, "<sleeping>\x00", 11);
                strncpy(myNeighbor->localIF, localIF, sizeof(myNeighbor->localIF));
                strncpy(myNeighbor->Chassis, "\x00", 1);
                strncpy(myNeighbor->Port, "\x00", 1);
                strncpy(myNeighbor->PortDesc, "\x00", 1);
                strncpy(myNeighbor->SysDesc, "\x00", 1);
                strncpy(myNeighbor->ManagementIP, "\x00", 1);
                strncpy(myNeighbor->VLAN, "\x00", 1);
                myNeighbor->next = NULL;
*/
		if (!*head) {
			*head=myNeighbor;
		}
		else {
        	        struct s_myNeighbor* b=*head;
	                while(b->next) b=b->next;
                	b->next=myNeighbor;
        	};
	}
        else { printf("ERROR allocating memory\n"); exit(1); };

        return myNeighbor;
}

int sx_write_short(unsigned char* buffer, u_int16_t data)
{ 
#if WORDS_BIGENDIAN
	buffer[0]=(data>>8)&0xff;
	buffer[1]=data&0xff;
#else
	buffer[1]=(data>>8)&0xff;
	buffer[0]=data&0xff;
#endif
	return 1;
};

int cdp_buffer_init(unsigned char* buffer, int len, unsigned char* myether)
{ 
	memset(buffer,0,len);

	buffer[0]=0x01;
	buffer[1]=0x00;
	buffer[2]=0x0c;
	buffer[3]=buffer[4]=buffer[5]=0xcc; 

	memcpy(buffer+6,myether,6);

	((struct cdp_header*)buffer)->dsap=0xaa;
	((struct cdp_header*)buffer)->ssap=0xaa;
	((struct cdp_header*)buffer)->control=0x03;
	((struct cdp_header*)buffer)->orgcode[2]=0x0c;
	sx_write_short((unsigned char*)&(((struct cdp_header*)buffer)->protocolId),
		htons(0x2000));

	buffer+=sizeof(struct cdp_header);

	buffer[0]=0x1; /* cdp version */
	buffer[1]=0xb4; /* cdp holdtime, 180 sec by default */
	buffer[2]=buffer[3]=0; /* checksum - will calculate later */

	return 4+sizeof(struct cdp_header);
};

unsigned lldp_encode_pdu(unsigned char* buffer, unsigned tlv, unsigned tlen, 
	unsigned char* data)
{ 
	buffer[0]=(tlv<<1)|(tlen>>8);
	buffer[1]=(tlen&0xff);
	if(tlen) { 
		memcpy(buffer+2,data,tlen);
	};
	return tlen+2;
};

int lldp_buffer_init(unsigned char* buffer, int len, unsigned char* myether)
{ 
	unsigned char macpdu[7];

	if(len<14+7) { 
		return 0;
	};
	memset(buffer,0,len);
	buffer[0]=0x01;
	buffer[1]=0x80;
	buffer[2]=0xc2;
	buffer[3]=buffer[4]=0x00;
	buffer[5]=0x0e;

	memcpy(buffer+6,myether,6);

	buffer[12]=0x88;
	buffer[13]=0xcc;

	macpdu[0]=0x04;
	memcpy(macpdu+1,myether,6);

	return 14+lldp_encode_pdu(buffer+14,1,7,macpdu);
};

int lldp_add_interface(unsigned char* buffer, unsigned size, char* iface)
{ 
	unsigned char hname[128];
	hname[0]=7;
	//strlcpy((char*)hname+1,iface,sizeof(hname)-1);
	memcpy((char*)hname+1,iface,sizeof(hname)-1);
	if(strlen(iface)+3>size) 
		return 0;
	return lldp_encode_pdu(buffer,2,strlen(iface)+1,hname);
};

int lldp_add_ttl(unsigned char* buffer, unsigned size, unsigned ttl)
{ 
	uint16_t tt=htons(ttl);
	if(size<4) 
		return 0;
	return lldp_encode_pdu(buffer,3,2,(unsigned char*)&tt);
};

int lldp_add_ifname(unsigned char* buffer, unsigned size, unsigned char* iface)
{ 
	if(size<strlen((char*)iface+2))
		return 0;
	return lldp_encode_pdu(buffer,4,strlen((char*)iface),iface);
};

int lldp_add_hostname(unsigned char* buffer, unsigned size)
{ 
	unsigned char hostname[128];
	
	if(gethostname((char*)hostname,sizeof(hostname))==-1) { 
		//strlcpy((char*)hostname,"Amnesiac",sizeof(hostname));
		memcpy((char*)hostname,"Amnesiac",sizeof(hostname));
	};

	if(size<strlen((char*)hostname)+2) 
		return 0;

	return lldp_encode_pdu(buffer,5,strlen((char*)hostname),hostname);
};

int lldp_add_sysdescr(unsigned char* buffer, unsigned size)
{ 
	struct utsname uts;
	unsigned char description[256];
	if(uname(&uts)!=0)
		return 0;
	snprintf((char*)description, sizeof(description), "%s %s %s %s",
		uts.sysname, uts.release, uts.version, uts.machine);
	if(size<strlen((char*)description)+2)
		return 0;
	return lldp_encode_pdu(buffer,6,strlen((char*)description),
		description);
};


int lldp_add_capabilities(unsigned char* buffer, unsigned size)
{ 
	if(size<6) 
		return 0;
	return lldp_encode_pdu(buffer,7,4,capabilities);
};

int lldp_add_address(unsigned char* buffer, unsigned size, uint32_t address)
{ 
	unsigned char imgmt[2+4+5+1];
	memset(imgmt,0,sizeof(imgmt));
	imgmt[0]=5;
	imgmt[1]=1;
	memcpy(imgmt+2,&address,4);
	imgmt[6]=1;
	if(size<sizeof(imgmt)+2) 
		return 0;
	return lldp_encode_pdu(buffer,8,sizeof(imgmt),imgmt);
};

#ifdef AF_INET6
int lldp_add_v6address(unsigned char* buffer, unsigned size, struct sockaddr_in6
	address)
{ 
	if(!IN6_IS_ADDR_UNSPECIFIED(&address.sin6_addr)) { 
		unsigned char i6mgmt[2+16+5+1];
		memset(i6mgmt,0,sizeof(i6mgmt));
		i6mgmt[0]=17;
		i6mgmt[1]=2;
		memcpy(i6mgmt+2,&address.sin6_addr,16);
		i6mgmt[18]=1;
		return lldp_encode_pdu(buffer,8,sizeof(i6mgmt),i6mgmt);
	};
	return 0;
};
#endif

int lldp_add_eolldp(unsigned char* buffer, unsigned size)
{ 
	if(size<2) 
		return 0;
	return lldp_encode_pdu(buffer,0,0,NULL);
};

int cdp_add_device_id(unsigned char* buffer, int len)
{ 
	char hostname[128];
	gethostname(hostname,128);

	if((strlen(hostname)+4)>len) return 0;

	*(u_int16_t*)buffer=htons(0x0001); /* type=deviceId */
	*((u_int16_t*)(buffer+2))=htons(strlen(hostname)+4); /* total length */
	memcpy(buffer+4,hostname,strlen(hostname));

	return strlen(hostname)+4;
};

int cdp_add_address(unsigned char* buffer, int len, u_int32_t addr)
{ 
	if(!addr) return 0;
	if(len<17) return 0;

	sx_write_short(buffer,htons(0x02)); 
	sx_write_short(buffer+2,htons(17)); 
	sx_write_long(buffer+4,htonl(1));
	buffer[8]=1; /* nlpid */
	buffer[9]=1; /* proto length */
	buffer[10]=0xcc; /* proto id: cc==IP */
	sx_write_short(buffer+11,htons(4));
	sx_write_long(buffer+13,addr); /* XXXX! */

	return 17;
};

int cdp_add_interface(unsigned char* buffer, int len, char* interface)
{ 
	if(!interface) return 0;
	if(len<(strlen(interface)+4)) return 0;

	sx_write_short(buffer,htons(0x0003)); /* type=PortId */
	sx_write_short(buffer+2,htons(strlen(interface)+4)); /* totallength*/
	memcpy(buffer+4,interface,strlen(interface));

	return strlen(interface)+4;
};

int cdp_add_capabilities(unsigned char* buffer, int len)
{ 
	if(len<8) return 0;

	sx_write_short(buffer,htons(0x0004)); /* type=Capabilities */
	sx_write_short(buffer+2,htons(8)); /* totallength*/
	sx_write_long(buffer+4,htonl(CDP_CAP_HOST)); /* no capabilities */

	return 8;
};

int cdp_add_software_version(unsigned char* buffer, int len)
{ 
	if((strlen(mysysname)+4)>len) return 0;

	sx_write_short(buffer,htons(0x0005)); /* type=software version */
	sx_write_short(buffer+2,htons(strlen(mysysname)+4)); 
		/* totallength*/
	memcpy(buffer+4,mysysname,strlen(mysysname));

	return strlen(mysysname)+4;
};

int cdp_add_platform(unsigned char* buffer, int len)
{ 
	if((strlen(myuname.machine)+4)>len) return 0;
	sx_write_short(buffer,htons(0x0006)); /* type=platform */
	sx_write_short(buffer+2,htons(strlen(myuname.machine)+4)); /* totallength*/
	memcpy(buffer+4,myuname.machine,strlen(myuname.machine));

	return strlen(myuname.machine)+4;
};

static uint16_t checksum(uint16_t *buffer, int size)
{
	unsigned long cksum=0;

	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(uint16_t);
	}

	if (size)
		cksum += *(uint8_t*)buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);

	return (uint16_t)(~cksum);
} 

unsigned short cdp_checksum(unsigned char *ptr, int length) {
  if (length % 2 == 0) {
    /* The doc says 'standard IP checksum', so this is what we do. */
    return checksum((u_short *)ptr, length);
  } else {
    /* An IP checksum is not defined for an odd number of bytes... */
    /* Tricky. */
    /* Treat the last byte as an unsigned short in network order. */

    int c = ptr[length-1];
    unsigned short *sp = (unsigned short *)(&ptr[length-1]);
    unsigned short ret;

    *sp = htons(c);
    ret = checksum((u_short *)ptr, length+1);
    ptr[length-1] = c;
    return ret;
  };
}

int usage()
{ 
        printf("Usage: cdpd-cp <-c | -l> [-i iface] [-m time] [-X]\n");
	printf("At least you need to specify -c or -l\n");
        printf("  -d      : debug mode ON\n");
        printf("  -h      : this help message\n");
        printf("  -i name : interface to exclude for sending cpd/lldp packets (usually sync interface)\n");
        printf("  -t time : maximum time to wait for an incomming CDP packet (60 sec by default)\n");
        printf("  -c      : send/listen CDP neighbors\n");
        printf("  -l      : send/liten LLDP neighbors\n");
        printf("  -X      : only SEND don't listen for any neighbor\n");
	return 0;
};


struct cdp_interface* cdp_interface_always(struct cdp_interface* list, const char* name, const unsigned char *mac)
{
	while(list) {
		//if(list->name && !strcmp(list->name,name) && !memcmp(list->eaddr,mac,6)) { 
		if(list->name && !memcmp(list->eaddr,mac,6)) {
			return list;
		};
		list=list->next;
	};
	return NULL;
};

struct cdp_interface* cdp_interface_add(struct cdp_interface** head, const char* name)
{
        struct cdp_interface* cdp;

        if(!name || !head) return NULL;

        cdp=malloc(sizeof(struct cdp_interface));
        if(!cdp) {
                fprintf(stderr,"malloc error: %s\n", strerror(errno));
                exit(1);
        };
        memset(cdp,0,sizeof(struct cdp_interface));
        cdp->name=strdup(name);

        cdp->pcap=pcap_open_live(name,0,0,0,cdp->errbuf);
        if(!cdp->pcap) {
                fprintf(stderr,"Unable to open PCAP on %s: %s\n", name, cdp->errbuf);
                free(cdp);
                return NULL;
        };

        if(pcap_datalink(cdp->pcap)!=DLT_EN10MB) {
                if(debug)
                        fprintf(stderr,"#DEBUG: Datalink: %s is not ethernet: %s\n", name,
                                pcap_datalink_val_to_description(pcap_datalink(cdp->pcap)));
                pcap_close(cdp->pcap);
                free(cdp);
                return NULL;
        };

        if(!*head) {
                *head=cdp;
        } else {
                struct cdp_interface* b=*head;
                while(b->next) b=b->next;
                b->next=cdp;
        };
        return cdp;
};



static int cdp_debug_packet(struct cdp_interface* cifa, int offset, unsigned char* buffer)
{ 
	int i, j;
	printf("#DEBUG: Sent over: %s, total length: %i\n", cifa->name, offset);
	for(i=0;i<offset/16;i++) { 
		printf("%4.4x ",i);
		for(j=0;j<16;j++)
			printf("%2.2x ",buffer[16*i+j]);
		for(j=0;j<8;j++) 
			if(isprint(buffer[16*i+j])) 
				printf("%c",buffer[16*i+j]);
			else 
				printf(".");
		printf(" ");
		for(j=8;j<16;j++) 
			if(isprint(buffer[16*i+j])) 
				printf("%c",buffer[16*i+j]);
			else 
				printf(".");

		printf("\n");
	};
	if(offset%16) { 
		i=offset/16;
		printf("%4.4x ",i);
		for(j=0;j<offset%16;j++)
			printf("%2.2x ",buffer[16*i+j]);
		for(j=offset%16; j<16; j++) 
			printf("   ");
		for(j=0;j<(offset%16>8?8:offset%16);j++) 
			if(isprint(buffer[16*i+j])) 
				printf("%c",buffer[16*i+j]);
			else 
				printf(".");
		printf(" ");
		for(j=8;j<offset%16;j++) 
			if(isprint(buffer[16*i+j])) 
				printf("%c",buffer[16*i+j]);
			else 
				printf(".");

		printf("\n");
	};
	return 0;
};
	

void lldp_decode_pdu(unsigned char* buffer, int *tlv, int *tlen)
{
        *tlv = buffer[0]>>1;
        *tlen = (256 * buffer[0]&0x01) + buffer[1];
}


void get_lldp_chassisid(unsigned char *tlvValue, int tlvLen, struct s_myNeighbor *myNeighbor)
{
	if (debug) printf("#DEBUG: Reading LLDP TLV Chassis. VALUE: %02x\n", tlvValue[0]);
        switch(tlvValue[0]) {
        case LLDPCHID_CHASSISCOM:
        case LLDPCHID_INTALIAS:
        case LLDPCHID_PORT:
        case LDDPCHID_IFACENAME:
        case LDDPCHID_LOCALLY:
                memcpy(myNeighbor->Chassis, (tlvValue + 1), tlvLen);
		myNeighbor->Chassis[tlvLen] = '\0';
                break;
        case LLDPCHID_MAC:
                tlvValue+=1;
                snprintf(myNeighbor->Chassis, 255, "%02x:%02x:%02x:%02x:%02x:%02x", tlvValue[0],tlvValue[1],tlvValue[2],tlvValue[3],tlvValue[4],tlvValue[5]);
                break;
        case LDDPCHID_NETWORK:
                tlvValue+=1;
                snprintf(myNeighbor->Chassis, 255, "%i.%i.%i.%i",tlvValue[0],tlvValue[1],tlvValue[2],tlvValue[3]);
                break;
        };
}


void get_lldp_portid(unsigned char *tlvValue, int tlvLen, struct s_myNeighbor *myNeighbor)
{
	if (debug) printf("#DEBUG: Reading LLDP TLV Port. VALUE: %02x\n", tlvValue[0]);
        switch(tlvValue[0]) {
        case LDDPPOID_INTALIAS:
        case LDDPPOID_PORTCOM:
        case LDDPPOID_IFACENAME:
        case LDDPPOID_CIRCUITID:
        case LDDPPOID_LOCALLY:
                memcpy(myNeighbor->Port, (tlvValue + 1), tlvLen);
		myNeighbor->Port[tlvLen] = '\0';
                break;
        case LDDPPOID_MAC:
                tlvValue+=1;
                snprintf(myNeighbor->Port, 255, "%02x:%02x:%02x:%02x:%02x:%02x", tlvValue[0],tlvValue[1],tlvValue[2],tlvValue[3],tlvValue[4],tlvValue[5]);
		break;
        case LDDPPOID_NET:
                tlvValue+=1;
                snprintf(myNeighbor->Port, 255, "%i.%i.%i.%i",tlvValue[0],tlvValue[1],tlvValue[2],tlvValue[3]);
                break;
        };
}


void get_lldp_mgmtip(unsigned char *tlvValue, struct s_myNeighbor *myNeighbor)
{
/* Only for IPv4/6 */

        tlvValue+=1;
        if ((int)tlvValue[0] == ADDR_FAMILY_IPV4) {
                tlvValue+=1;
                snprintf(myNeighbor->ManagementIP,sizeof(myNeighbor->ManagementIP), "%i.%i.%i.%i",tlvValue[0],tlvValue[1],tlvValue[2],tlvValue[3]);
        } else if ((int)tlvValue[0] == ADDR_FAMILY_IPV6) {
                tlvValue+=1;
                snprintf(myNeighbor->ManagementIP,sizeof(myNeighbor->ManagementIP), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", tlvValue[0],tlvValue[1],tlvValue[2],tlvValue[3],tlvValue[4],tlvValue[5],tlvValue[6],tlvValue[7],tlvValue[8],tlvValue[9],tlvValue[10],tlvValue[11],tlvValue[12],tlvValue[13],tlvValue[14],tlvValue[15]);
        }
}


void get_lldp_org(unsigned char *tlvValue, struct s_myNeighbor *myNeighbor)
{
/* For the time being only interested in VLAN */

        unsigned char *tempBuffer;
        unsigned int i;

        tempBuffer = (unsigned char *)(malloc (10));

        memcpy(tempBuffer, tlvValue, 3);
        /* First char is 0x00, so I need to use a trick converting everything to integer first */
        i = tempBuffer[2] + ((uint16_t)tempBuffer[1] << 8) + ((uint16_t)tempBuffer[0] << 16);
        if (i == LLDP_IEEE8021) {
                tlvValue+=3;
                if (*tlvValue == LLDP_VLANID) {
                        memcpy(tempBuffer, tlvValue + 1, 2);
                        i = tempBuffer[1] + ((uint16_t)tempBuffer[0] << 8);
                        snprintf(myNeighbor->VLAN, sizeof(myNeighbor->VLAN), "%d", i);
                }
        }

        free(tempBuffer);
}

char *replace(const char *s, char ch, const char *repl) {
    int count = 0;
    const char *t;

    for(t=s; *t; t++)
        count += (*t == ch);

    size_t rlen = strlen(repl);
    char *res = malloc(strlen(s) + (rlen-1)*count + 1);
    char *ptr = res;
    for(t=s; *t; t++) {
        if(*t == ch) {
            memcpy(ptr, repl, rlen);
            ptr += rlen;
        } else {
            *ptr++ = *t;
        }
    }
    *ptr = 0;
    return res;
}

void print_neighbor(struct s_myNeighbor* myNeighbor)
{
	if (debug) printf("#DEBUG: Printing information.\n");
	while(myNeighbor) {
		if (strcmp(myNeighbor->SysName,"<sleeping>")) {
		        printf("\nNeighbor found in: %s\n", myNeighbor->localIF);
		        printf("Chassis: %s\n", myNeighbor->Chassis);
		        printf("Port: %s\n", myNeighbor->Port);
		        printf("PortDesc: %s\n", myNeighbor->PortDesc);
		        printf("SysName: %s\n", myNeighbor->SysName);
		        printf("SysDesc: %s\n", replace(myNeighbor->SysDesc, '\n', "\\\\n"));
		        printf("Management IP: %s\n", myNeighbor->ManagementIP);
		        printf("VLAN: %s\n", myNeighbor->VLAN);
		};
		myNeighbor=myNeighbor->next;
	};
}




int readLLDPpacket(const unsigned char *packet, struct s_myNeighbor *myNeighbor) {
/* myNeighbor is pointing to the one for the specific interface */

/* Ethernet frame 14 bytes:
 *  source mac 6 bytes
 *  destination mac 6 bytes
 *  type 2 bytes
 *
 *  (there is no LLC header)
 *  
 *  LLDP Packet
 *  Version: 1 byte
 *  TTL: 1 byte
 *  Checksum: 2 byte
 *  Type: 2 byte
 *  Length: 2 byte
 *  Value: variable
 *  
 */
	unsigned char* lldpData;
	unsigned char tlvTypeLen[2];
	int tlvType=0, tlvLen=0, iSecure=0;

	unsigned char* tlvValue;

	tlvValue = (unsigned char *)(malloc(1500));


	lldpData = (unsigned char *)packet + SIZE_ETHERNET;
	strncpy(myNeighbor->SysName, "N/A\x00", 4); // At least we received something...
	do {
	        memcpy(tlvTypeLen, lldpData, 2);

	        lldp_decode_pdu(tlvTypeLen, &tlvType, &tlvLen);
	        if (tlvType) {
	                memcpy(tlvValue, (lldpData + 2), tlvLen);
	        }
	        switch(tlvType) {
	                case LLDP_CHASSISID:
				if (debug) printf("#DEBUG: LLDP TLV Chassis found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        get_lldp_chassisid(tlvValue, tlvLen, myNeighbor);
	                break;
	                case LDDP_PORTID:
				if (debug) printf("#DEBUG: LLDP TLV PortID found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        get_lldp_portid(tlvValue, tlvLen, myNeighbor);
	                break;
	                case LLDP_PORTDESC:
				if (debug) printf("#DEBUG: LLDP TLV PortDesc found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        memcpy(myNeighbor->PortDesc, tlvValue, tlvLen);
	                        myNeighbor->PortDesc[tlvLen] = '\0';
	                break;
	                case LLDP_SYSNAME:
				if (debug) printf("#DEBUG: LLDP TLV SysName found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        memcpy(myNeighbor->SysName, tlvValue, tlvLen);
	                        myNeighbor->SysName[tlvLen] = '\0';
	                break;
	                case LLDP_SYSDESC:
				if (debug) printf("#DEBUG: LLDP TLV SysDesc found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        memcpy(myNeighbor->SysDesc, tlvValue, tlvLen);
	                        myNeighbor->SysDesc[tlvLen] = '\0';
	                break;
	                case LLDP_MGMTADDR:
				if (debug) printf("#DEBUG: LLDP TLV Mgmt IP found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        get_lldp_mgmtip(tlvValue, myNeighbor);
	                break;
	                case LLDP_ORG:
				if (debug) printf("#DEBUG: LLDP TLV Organization found (type: %i, length: %i)\n", tlvType, tlvLen);
	                        get_lldp_org(tlvValue, myNeighbor);
	                break;
			default:
				if (debug) printf("#DEBUG: LLDP TLV GENERIC found (type: %i, length: %i)\n", tlvType, tlvLen);
			break;
	        } // switch
	        lldpData += 2 + tlvLen;
	        iSecure++;
	}  while (tlvType != 0 && iSecure < 30);
	if (debug) printf("#DEBUG: END LLDP PACKET\n");
	
	return 0;
}


int readCDPpacket(const unsigned char *packet, struct s_myNeighbor *myNeighbor) {
/* myNeighbor is pointing to the one for the specific interface */

/* CDP Packet
 * Version: 1 byte
 * TTL: 1 byte
 * Checksum: 2 byte
 * Type: 2 byte
 * Length: 2 byte
 * Value: variable
 *
 */

        int ipacketLen;
        unsigned char packetLen[2];

        unsigned char* cdpData;

        unsigned char cdpVer[1];
        unsigned char cdpType[2];
        unsigned char cdpLength[2];
        unsigned char* cdpValue;
        unsigned char* addrbuff;
        unsigned char IPaddr[16];
        unsigned char* IPbuff;

        uint16_t offset=0,ilength=0;
        int numberAddr, i;
	int iSecure=0;

        cdpValue = (unsigned char *)(malloc(1500));
        IPbuff = (unsigned char *)(malloc(1500));


	memcpy(packetLen, packet + 12, 2);
	ipacketLen = packetLen[1] + ((uint16_t)packetLen[0] << 8) - SIZE_LLC_HEADER - 4; // 4 = Version + TTL + Checksum
	if (debug) printf("#DEBUG: Packet Length: %i \n", ipacketLen);

	cdpData = (unsigned char *) packet + SIZE_ETHERNET + SIZE_LLC_HEADER;
	memcpy(cdpVer, cdpData, 1);
	cdpData+=4;
	ilength=0;
	offset=0;

	if (debug) printf("#DEBUG: Captured CDP packet version: %02x\n", cdpVer[0]);
	

	while (offset < ipacketLen && iSecure < 30) {
        	cdpData+= ilength;

	        memcpy(cdpType, cdpData, 2);
	        memcpy(cdpLength, cdpData + 2, 2);
	        ilength = cdpLength[1] + ((uint16_t)cdpLength[0] << 8);
		memcpy(cdpValue, (cdpData + 4), ilength);
	
	        switch(cdpType[1]){
	                case CDP_DEVICEID:
				if (debug) printf("#DEBUG: CDP TLV DeviceID received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
                                memcpy(myNeighbor->SysName, cdpValue, ilength);
                                myNeighbor->SysName[ilength] = '\0';
	                break;
	                case CDP_MGMT_ADDR:
				addrbuff = (unsigned char *)(malloc(1500));
				if (debug) printf("#DEBUG: CDP TLV Mgmt IP received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
	                        addrbuff = cdpValue + 3; // 4 bytes for number of IPs
	                        numberAddr = *(addrbuff);
	                        addrbuff = addrbuff + 1;
	                        if (debug) printf("#DEBUG: CDP TLV Mgmt number of IPs: %i\n", numberAddr);
	                        for(i=1;i<=numberAddr;i++) {
	                                if (*addrbuff == CDP_ADDR_NLPID) {
	                                        addrbuff+= 2; // Len is always 1 with NLPID, so skip this field
	                                        if (*addrbuff == CDP_ADDR_PROTO_IPV4) {
	                                                // If it's IPv4, length for the address will be always 4 so we skip the length address field
	                                                addrbuff+=3;
	                                                memcpy(IPaddr, addrbuff, 4);
							/* PENDING: To store all IPs instead of taking the last one */
							snprintf(myNeighbor->ManagementIP, sizeof(myNeighbor->ManagementIP), "%i.%i.%i.%i",(int)IPaddr[0],(int)IPaddr[1],(int)IPaddr[2],(int)IPaddr[3]);
                	                                addrbuff+=4;
                        	                } else {
                                	                // offset = protolength (1) + address length + address itself
                                        	        addrbuff+=1 + 2 + *(addrbuff + 2);
	                                        }	
	                                } else if (*addrbuff == CDP_ADDR_8022) {
	                                        addrbuff+=1;
        	                                if (*addrbuff == 8) { // For IPv6 length = 8
                	                                addrbuff+=1;
                        	                        memcpy(IPaddr, addrbuff, 8);
                                	                if (IPbuff[0] == 0xaa && IPbuff[6] == 0x08) {
                                        	                addrbuff+=8;
                                                	        memcpy(IPaddr, addrbuff, 16);
                                                        	snprintf(myNeighbor->ManagementIP, sizeof(myNeighbor->ManagementIP), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",IPaddr[0],IPaddr[1],IPaddr[2],IPaddr[3],IPaddr[4],IPaddr[5],IPaddr[6],IPaddr[7],IPaddr[8],IPaddr[9],IPaddr[10],IPaddr[11],IPaddr[12],IPaddr[13],IPaddr[14],IPaddr[15]);
						                addrbuff+=16;
	                                                } else {
	                                                        addrbuff+=8 + 2 + *(addrbuff + 9);
		                                                }
	                                        } else {
	                                                // if it's not 8 is 3.
	                                                // offset = proto length + address length + address itself
	                                                addrbuff+=1 + 3 + 2 + *(addrbuff + 5);
	                                        }
	                                }
	                        }
				addrbuff=NULL;
				free(addrbuff);
	                break;
			case CDP_VER:
				if (debug) printf("#DEBUG: CDP TLV Version received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
                                memcpy(myNeighbor->SysDesc, cdpValue, ilength);
                                myNeighbor->SysDesc[ilength] = '\0';
			break;
	                case CDP_PORTID:
				if (debug) printf("#DEBUG: CDP TLV PortID received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
				memcpy(myNeighbor->Port, cdpValue, ilength);
                                myNeighbor->Port[ilength] = '\0';
	                break;
	                case CDP_PLAT:
				if (debug) printf("#DEBUG: CDP TLV Platform received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
                                memcpy(myNeighbor->Chassis, cdpValue, ilength);
                                myNeighbor->Chassis[ilength] = '\0';
	                break;
			case CDP_NATIVEVLAN:
				addrbuff = (unsigned char *)(malloc(1500));
				if (debug) printf("#DEBUG: CDP TLV Nat. VLAN received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
				memcpy(addrbuff, cdpValue, ilength);
                        	i = addrbuff[1] + ((uint16_t)addrbuff[0] << 8);
                        	snprintf(myNeighbor->VLAN, sizeof(myNeighbor->VLAN), "%d", i);
				addrbuff=NULL;
				free(addrbuff);
				
			break;
			default:
				if (debug) printf("#DEBUG: CDP TLV GENERIC received (Type: %02x%02x Len: %i Off: %i)\n", cdpType[0], cdpType[1], ilength, offset);
			break;
	        }
		iSecure++;
	        offset+=ilength; // Type and len field are included already in len
	} // while offset
	if (debug) printf("#DEBUG: END CDP PACKET\n");
	cdpData = NULL;
	cdpValue = NULL;
	IPbuff = NULL;
	free(cdpData);
        free(cdpValue);
        free(IPbuff);

	return 0;
}

void read_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        struct ether_header *eptr;

        unsigned char *ptr; /* printing out hardware header info */

        int i, lldpCDP = 0; // 0 lldp 1 CDP

	struct s_myNeighbor* myNeighbor=(struct s_myNeighbor *)(args);

	alarm(0);

        /* lets start with the ether header... */
        eptr = (struct ether_header *) packet;
	lldpCDP =  (memcmp(eptr->ether_dhost, "\x01\x80\xC2\x00\x00\x0E", 6) && memcmp(eptr->ether_dhost, "\x01\x80\xC2\x00\x00\x03", 6) && memcmp(eptr->ether_dhost, "\x01\x80\xC2\x00\x00\x00", 6));
	
	  
	if (debug) printf("#DEBUG: EtherType %x (lldpCDP val %i)\n", eptr->ether_type, lldpCDP);

        ptr = eptr->ether_dhost;
        i = ETHER_ADDR_LEN;
        if (debug) {
                printf("#DEBUG: Destination Address:  ");
                do {
                        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
                }while(--i>0);
                printf("\n");
        }
        ptr = eptr->ether_shost;
        i = ETHER_ADDR_LEN;
        if (debug) {
                printf("#DEBUG: Source Address:  ");
                do{
                        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
                }while(--i>0);
                printf("\n");
        }
        if (lldpCDP) {
		printf("Noisy CDP neighbor found.\n");
                readCDPpacket(packet, myNeighbor);
	} else {
		printf("Noisy LLDP neighbor found.\n");
                readLLDPpacket(packet, myNeighbor);
	}
}

void stopCapture(int sig) {
	signal(SIGALRM, SIG_IGN);
  	pcap_breakloop (capturehandle);
	printf("Your neighbor is quiet. No CDP/LLDP packet received.\n");
	signal(SIGALRM, stopCapture);	
}



int init_ifaces(struct cdp_interface** ifaces, struct s_myNeighbor** myNeighbors, char* ifaceExcluded)
{
	pcap_if_t *alldevs=NULL;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int numIF=0;
	unsigned char mac[6];


        /* Initialising all interfaces.. */
        if (debug) printf("#DEBUG: Initialazing interface...\n");
        pcap_findalldevs(&alldevs,errbuf);
        for(dev=alldevs;dev;dev=dev->next) {
                if (debug) printf("#DEBUG: Interface name: %s\n", dev->name);
                if(!strcmp(dev->name,"all")) continue;
                if(!strcmp(dev->name,ifaceExcluded)) continue;
                if(dev->flags&PCAP_IF_LOOPBACK) continue;
                if(!dev->addresses) continue;

		/* Checking MAC */
                struct ifreq ifr;
                int sockfd=socket(AF_INET,SOCK_DGRAM,0);
                if(sockfd<0) {
                	fprintf(stderr,"socket: %s\n",strerror(errno));
			continue;
        	} else {
	                memset(&ifr, 0, sizeof(struct ifreq));
        	        memcpy(ifr.ifr_name,dev->name,sizeof(ifr.ifr_name));
	                if(ioctl(sockfd,SIOCGIFHWADDR,&ifr)<0) {
	                	fprintf(stderr,"ioctl(SIOCGIFHWADDR): %s (name: %s, oname: %s\n", strerror(errno), ifr.ifr_name, dev->name);
				continue;
	                } else {
		                memcpy(mac,ifr.ifr_ifru.ifru_hwaddr.sa_data,6);
				close(sockfd);
	        	        if(debug) {
		                	printf("#DEBUG: %s: %s (Linux method)\n", dev->name, ether_ntoa((struct ether_addr*)mac));
		                };
			};
		};

		if(cdp_interface_always(*ifaces, dev->name, mac)) continue;
                struct cdp_interface* cdp;
                struct s_myNeighbor* newNeighbor;
                pcap_addr_t* addr;

		cdp=cdp_interface_add(*&ifaces,dev->name);
                if(cdp == NULL) continue;
		if(debug) printf("#DEBUG: Added new interface %s with mac %s\n", cdp->name, ether_ntoa((struct ether_addr*)mac));
		memcpy(cdp->eaddr,mac,6);
		newNeighbor=addNeighbor(*&myNeighbors, cdp->name, cdp->eaddr);
		numIF++;
                for(addr=dev->addresses; addr; addr=addr->next) {
                        if(addr->addr && addr->addr->sa_family==AF_INET) {
                                if(!cdp->address.sin_addr.s_addr) {
                                        cdp->address=*(struct sockaddr_in*)addr->addr;
                                };
#ifdef AF_INET6
                        } else if(addr->addr && addr->addr->sa_family==AF_INET6) {
                                memcpy(&cdp->ipv6address, addr->addr, sizeof(struct sockaddr_in6));
#endif
                        };
                }; // for addr
        }; // for dev

        pcap_freealldevs(alldevs);

	return numIF;
}

int main(int argc, char* argv[])
{ 
	char c;
	int ret=0,listentimeout=60;
	unsigned char buffer[1600];
	int offset;
	int interfaceNum;
	int sendlldp=0, sendcdp=0;
	struct cdp_interface* ifaces=NULL;
	struct s_myNeighbor* myNeighborhood=NULL;
	char ifaceExcluded[32] = "";
	char errbuf[PCAP_ERRBUF_SIZE] = "";

	struct cdp_interface* cifa;
	struct s_myNeighbor* myNeighbor;

	struct bpf_program fp;      /* hold compiled program     */
	char *filter=NULL;

	int numIF=0;

        capabilities[1]=0x10;
        capabilities[3]=0x10;

	printf("CDP/LLDP Protocol listener for Checkpoint Firewalls v1.0 (%s)\n",pcap_lib_version());

	if (argc < 2) {
		usage();
		exit(1);
	};

        while((c=getopt(argc,argv,"dclXhi:t:"))!=EOF) {
        switch(c) {
                case 'd': debug=1;
                        break;
                case 'i':
                        strcpy(ifaceExcluded, optarg);
                        if (debug) printf("Interface -i: %s\n", ifaceExcluded);
                        break;
                case 't':
                        listentimeout=atoi(optarg);
                        if(listentimeout<=0) {
                                printf("Wrong value for waiting time - using default 60 sec\n");
                                listentimeout=60;
                        };
                        break;
		case 'c':
			sendcdp=1;
			break;
		case 'l':
			sendlldp=1;
			break;
		case 'X':
			listentimeout=0;
			break;
                default: 
			usage();
                        exit(1);
        };
        };
	numIF = init_ifaces(&ifaces, &myNeighborhood, ifaceExcluded);
        if(!ifaces) {
                printf("No valid interfaces found, exiting..\n");
                exit(1);
        };

	if (debug) {
		printf("#DEBUG: Interfaces with UNIQUE MAC ");
		cifa=ifaces;
		while(cifa) {
			printf(" %s ", cifa->name);
			cifa=cifa->next;
		};
		printf("\n");
	};

        uname(&myuname);
        snprintf(mysysname,sizeof(mysysname),"%s %s %s", myuname.sysname, myuname.release, myuname.version);
	
	signal(SIGALRM, stopCapture);

	interfaceNum=0;
	cifa=ifaces;
	myNeighbor=myNeighborhood;
        while(cifa) {
		if (listentimeout) {
			alarm(listentimeout);
			printf("Listening for neighbors noise in %s (I'll wait %i seconds)...\n", cifa->name, listentimeout);
			if (debug) printf("#DEBUG: Starting capturing packets in %s \n", cifa->name);
			capturehandle = pcap_open_live(cifa->name,SNAP_LEN,1,1000,errbuf);
			if(capturehandle == NULL)
			{
			        printf("pcap_open_live(): %s\n",errbuf);
			        exit(1);
			}
			if (debug) printf("#DEBUG: Applying filter\n");
			if (sendcdp) {
				if (sendlldp)
					filter = "(ether host 01:00:0c:cc:cc:cc and ether[16:4] = 0x0300000C and ether[20:2] == 0x2000) or ether proto 0x88cc";
				else
					filter = "ether host 01:00:0c:cc:cc:cc and ether[16:4] = 0x0300000C and ether[20:2] == 0x2000";
			} else filter = "ether proto 0x88cc";
			/* non-optimized no netmask, not interested in any IPv4 packets, only CDP/LLDP */
			if(pcap_compile(capturehandle,&fp,filter,0,0) == -1)
	        		{ fprintf(stderr,"Error calling pcap_compile: %s\n", pcap_geterr(capturehandle)); exit(1); }
			/* set the compiled program as the filter */
			if(pcap_setfilter(capturehandle,&fp) == -1)
	       			{ fprintf(stderr,"Error setting filter\n"); exit(1); }
			if (debug) printf("#DEBUG: Listening for packets (timeout %i)...\n", listentimeout);
			
			//pcap_loop(capturehandle, 1, read_packet, (u_char*)&allMyNeighbors[interfaceNum]);
			pcap_loop(capturehandle, 1, read_packet, (u_char*)myNeighbor);
			interfaceNum++;
		}; // listentimeout

		printf("Sending CDP/LLDP through %s\n", cifa->name);
		if (sendcdp) {
			offset=0;
			offset=cdp_buffer_init(buffer,sizeof(buffer),cifa->eaddr);		
			offset+=cdp_add_device_id(buffer+offset,sizeof(buffer)-offset);
			offset+=cdp_add_address(buffer+offset,sizeof(buffer)-offset,cifa->address.sin_addr.s_addr);
			offset+=cdp_add_interface(buffer+offset,sizeof(buffer)-offset,cifa->name);
			offset+=cdp_add_capabilities(buffer+offset,sizeof(buffer)-offset);
			offset+=cdp_add_software_version(buffer+offset,sizeof(buffer)-offset);
	
			offset+=cdp_add_platform(buffer+offset,sizeof(buffer)-offset);
		
			((struct cdp_header*)buffer)->length=htons(offset-14);
			
			*(u_short*)(buffer+sizeof(struct cdp_header)+2)=cdp_checksum(buffer+sizeof(struct cdp_header),offset-sizeof(struct cdp_header));
			if(pcap_inject(cifa->pcap,buffer,offset)!=offset){
				printf("%s: wrote only %i bytes: %s\n", cifa->name, ret, strerror(errno));
			};
				printf("CDP packet sent for %s\n", cifa->name);
				if(debug==1) { 
					cdp_debug_packet(cifa,offset,buffer);
				};
			};
			if (sendlldp) {
				offset=0;
				offset=lldp_buffer_init(buffer,sizeof(buffer),cifa->eaddr);
				offset+=lldp_add_interface(buffer+offset,sizeof(buffer)-offset, cifa->name);
				offset+=lldp_add_ttl(buffer+offset,sizeof(buffer)-offset,43200); // 12H for timeout
				offset+=lldp_add_ifname(buffer+offset,sizeof(buffer)-offset, (unsigned char*)cifa->name);
				offset+=lldp_add_hostname(buffer+offset,sizeof(buffer)-offset);
				offset+=lldp_add_sysdescr(buffer+offset,sizeof(buffer)-offset);
				offset+=lldp_add_capabilities(buffer+offset,sizeof(buffer)-offset);
				offset+=lldp_add_address(buffer+offset,sizeof(buffer)-offset,cifa->address.sin_addr.s_addr);
#ifdef AF_INET6
				offset+=lldp_add_v6address(buffer+offset,sizeof(buffer)-offset,cifa->ipv6address);
#endif
				offset+=lldp_add_eolldp(buffer+offset,sizeof(buffer)-offset);
				if(pcap_inject(cifa->pcap,buffer,offset)!=offset){
					printf("error writing to %s: %s\n", cifa->name,strerror(errno));
				};
				printf("LLDP packet sent for %s\n", cifa->name);
				if(debug==1) { 
					cdp_debug_packet(cifa,offset,buffer);
				};
			};

			cifa=cifa->next;
			myNeighbor=myNeighbor->next;
		};  /* all interfaces done */

	print_neighbor(myNeighborhood);
	printf("CPD-CP Execution finish.\n");
	return 0;
};
