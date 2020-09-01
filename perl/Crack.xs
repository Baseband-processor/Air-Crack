#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "Ctxs.h"
#include <netinet/in.h>
#include <linux/socket.h>


#define ALLEGE(c)                                                              \
	do                                                                         \
	{                                                                          \
		if (!(c))                                                              \
		{                                                                      \
			fprintf(stderr, "FAILED:%s:%d: %s\n", __FILE__, __LINE__, #c);     \
			abort();                                                           \
		}                                                                      \
	} while (0)

#define SUCCESS 0
#define FAILURE 1
#define RESTART 2

#define STD_OPN 0x0001u
#define STD_WEP 0x0002u
#define STD_WPA 0x0004u
#define STD_WPA2 0x0008u

#define NULL_MAC (unsigned char *) "\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE (unsigned char *) "\x01\x80\xC2\x00\x00\x00"

#define ENC_WEP 0x0010u
#define ENC_TKIP 0x0020u
#define ENC_WRAP 0x0040u
#define ENC_CCMP 0x0080u
#define ENC_WEP40 0x1000u
#define ENC_WEP104 0x0100u
#define ENC_GCMP 0x4000u
#define ENC_GMAC 0x8000u

#define ENC_FIELD                                                              \
	(ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104         \
	 | ENC_GCMP                                                                \
	 | ENC_GMAC)

#define AUTH_OPN 0x0200u
#define AUTH_PSK 0x0400u
#define AUTH_MGT 0x0800u
#define AUTH_CMAC 0x10000u
#define AUTH_SAE 0x20000u
#define AUTH_OWE 0x40000u

#define AUTH_FIELD                                                             \
	(AUTH_OPN | AUTH_PSK | AUTH_CMAC | AUTH_MGT | AUTH_SAE | AUTH_OWE)


#define AMOUNT_ARGUMENTS_IGNORE 2
#define EXIT_SUCCESS 0

#define QUEUE_MAX 666


#define SESSION_ARGUMENTS_LINE 4
#define AC_SESSION_CWD_LINE 0
#define AC_SESSION_BSSID_LINE 1
#define AC_SESSION_WL_SETTINGS_LINE 2
#define AC_SESSION_ARGC_LINE 3

#define NET_SET_CHAN 1
#define NET_GET_CHAN 1
#define NET_GET_MAC 1
#define NET_MAC 1
#define NET_GET_MONITOR 1
#define NET_WRITE 1
#define NET_RC  1
#define NET_PACKET 1
#define NET_GET_RATE 1
#define NET_SET_RATE 1	


#define BEACON_FRAME 0x80
#define PROBE_RESPONSE 0x50
#define AUTHENTICATION 0xB0
#define ASSOCIATION_REQUEST 0x00

#define LINKTYPE_PRISM_HEADER 119
#define LINKTYPE_RADIOTAP_HDR 127
#define LINKTYPE_PPI_HDR 192

#define O_BINARY 0
#define WPA_DATA_KEY_BUFFER_LENGTH 128

#define MAX_DICTS 128

#define ASCII_LOW_T 0x21
#define ASCII_HIGH_T 0x7E
#define ASCII_VOTE_STRENGTH_T 150
#define ASCII_DISREGARD_STRENGTH 1

#define MAX_IFACE_NAME 64


#define TEST_MIN_IVS 4
#define TEST_MAX_IVS 32

#define PTW_TRY_STEP 5000

#define KEYHSBYTES PTW_KEYHSBYTES

#define MAX_THREADS 256



#define ASCII_LOW_T 0x21
#define ASCII_HIGH_T 0x7E
#define ASCII_VOTE_STRENGTH_T 150
#define ASCII_DISREGARD_STRENGTH 1

#define TEST_MIN_IVS 4
#define TEST_MAX_IVS 32

#define PTW_TRY_STEP 5000

#define KEYHSBYTES PTW_KEYHSBYTES

#define MAX_THREADS 256

#define CLOSE_IT 100000
#define IEEE80211_FC1_DIR_FROMDS 0x02 
#define KEYLIMIT 1000000

#define N_ATTACKS 17

typedef struct net_hdr{
	uint8_t nh_type;
	uint32_t nh_len;
	uint8_t nh_data[0];
}NET_HDR; 


typedef struct communication_options{
	uint8_t f_bssid[6];
	uint8_t f_dmac[6];
	uint8_t f_smac[6];
	uint8_t f_netmask[6];
	int f_minlen;
	int f_maxlen;
	int f_type;
	int f_subtype;
	int f_tods;
	int f_fromds;
	int f_iswep;

	uint8_t deauth_rc;
	int r_nbpps;
	unsigned int r_fctrl;
	uint8_t r_bssid[6];
	uint8_t r_dmac[6];
	uint8_t r_smac[6];
	uint8_t r_trans[6];
	uint8_t r_dip[4];
	uint8_t r_sip[4];
	char r_essid[33];
	int r_fromdsinj;
	char r_smac_set;

	char ip_out[16]; 
	char ip_in[16];
	int port_out;
	int port_in;

	char * iface_out;
	char * s_face;
	char * s_file;
	uint8_t * prga;
	size_t prgalen;

	int a_mode;
	int a_count;
	int a_delay;
	int f_retry;

	int ringbuffer;
	int ghost;

	int delay;
	int npackets;

	int fast;
	int bittest;

	int nodetect;
	int ignore_negative_one;
	int rtc;

	int reassoc;

	int crypt;
	uint8_t wepkey[64];
	size_t weplen;

	int f_index; 
	FILE * f_txt; 
	FILE * f_kis; 
	FILE * f_kis_xml; 
	FILE * f_gps; 
	FILE * f_cap; 
	FILE * f_ivs; 
	FILE * f_xor; 
	FILE * f_logcsv;

	char * f_cap_name;
	char * prefix;

	int output_format_pcap;
	int output_format_csv;
	int output_format_kismet_csv;
	int output_format_kismet_netxml;
	int output_format_log_csv;

	int usegpsd; 
	int record_data; 

	unsigned char sharedkey[3][4096]; 
	time_t sk_start;
	size_t sk_len;
	size_t sk_len2;

	int quiet;
	int verbose;
}opt;

typedef struct  netqueue{
	unsigned char q_buf[2048];
	int q_len;
	struct netqueue * q_next;
	struct netqueue * q_prev;
}NETQUEUE;



typedef struct priv_net{
	int pn_s;
	NETQUEUE *pn_queue;
	NETQUEUE *pn_queue_free;
	int pn_queue_len;
}PRIVATE_NET;
	

typedef struct packet_elt_header{
	struct packet_elt * first;
	struct packet_elt * current;
	struct packet_elt * last;
	int nb_packets;
	int average_signal; 
}_packet_elt_head;

typedef struct {
  unsigned long s_addr;  
}in_addr;

typedef struct in_addr IN_ADDR;

typedef struct  {
    short            sin_family;   
    unsigned short   sin_port;   
    IN_ADDR   sin_addr;     
    char    sin_zero[8]; 
}sockaddr_in;

typedef struct sockaddr_in SOCKADDR_IN;


typedef bool BOOLEAN;
typedef struct WPS_INFO         WPS_INFORMATION;
typedef rc4test_func            RC4TEST;
typedef struct WPA_hdsk         WPA_HANDSHAKE;
typedef struct n_channel_info   N_CHANNEL_INFO;
typedef struct ac_channel_info  AC_CHANNEL_INFO;
typedef struct PTW_tableentry   PTW_TABLEENTRY;
typedef struct PTW_session      PTW_SESSION;
typedef struct PTW_attackstate  PTW_STATE;
static struct pcap_file_header _pfh_in;
static struct pcap_file_header _pfh_out;

typedef struct  tx_info{
	uint32_t ti_rate;
}Tx;

typedef struct rx_info{
	uint64_t ri_mactime;
	int32_t ri_power;
	int32_t ri_noise;
	uint32_t ri_channel;
	uint32_t ri_freq;
	uint32_t ri_rate;
	uint32_t ri_antenna;
}Rx;


typedef struct wif {
	int (*wi_read)(struct wif * wi,
				   struct timespec * ts,
				   int * dlt,
				   unsigned char * h80211,
				   int len,
				   struct rx_info * ri);
	int (*wi_write)(struct wif * wi,
					struct timespec * ts,
					int dlt,
					unsigned char * h80211,
					int len,
					struct tx_info * ti);
	int (*wi_set_ht_channel)(struct wif * wi, int chan, unsigned int htval);
	int (*wi_set_channel)(struct wif * wi, int chan);
	int (*wi_get_channel)(struct wif * wi);
	int (*wi_set_freq)(struct wif * wi, int freq);
	int (*wi_get_freq)(struct wif * wi);
	void (*wi_close)(struct wif * wi);
	int (*wi_fd)(struct wif * wi);
	int (*wi_get_mac)(struct wif * wi, unsigned char * mac);
	int (*wi_set_mac)(struct wif * wi, unsigned char * mac);
	int (*wi_set_rate)(struct wif * wi, int rate);
	int (*wi_get_rate)(struct wif * wi);
	int (*wi_set_mtu)(struct wif * wi, int mtu);
	int (*wi_get_mtu)(struct wif * wi);
	int (*wi_get_monitor)(struct wif * wi);

	void * wi_priv;
	char wi_interface[MAX_IFACE_NAME];
}WIF;


typedef struct timespec     TIME;
typedef struct timeval     TIMEVALUATE;
typedef struct AP_info      AP;
typedef struct ST_info      ST;
typedef struct tm           TM;

typedef pthread_mutex_t PTHREAD;

typedef struct session{
	char * filename;
	char * working_dir; 
	unsigned char bssid[6]; 
	unsigned char wordlist_id; 
	int64_t pos; 
	long long int nb_keys_tried;
	int argc; 
	char ** argv; 
	PTHREAD mutex; 
	unsigned char is_loaded;
}SESSION;

typedef struct session      SESSION;
typedef struct packet_elt   PACKET_ELT;

typedef struct ac_crypto_engine_t  AC_CRYPTO;

MODULE = Air::Crack   PACKAGE = Air::Crack
PROTOTYPES: DISABLE
 
void 
airpcap_close()


int 
airpcap_get_mac(mac)
	void * mac

int
airpcap_set_mac(mac)
	void * mac

int
airpcap_sniff(buf, length, ri)
	void * buf
	int length
	Rx * ri
	

int 
airpcap_inject(buf, length, ti)
	void * buf
	int length
	Tx * ti
	
int
airpcap_init(parameter)
	char *parameter

int
airpcap_set_chan(channel)
	int channel

int
isAirpcapDevice(interface)
	const char * interface

int 
getFrequencyFromChannel(channel)
	int channel


int
getChannelFromFrequency(frequency)
	int frequency
CODE:
	if (frequency >= 2412 && frequency <= 2472)
		return (frequency - 2407) / 5;
	else if (frequency == 2484)
		return 14;
	else if (frequency >= 4920 && frequency <= 6100)
		return (frequency - 5000) / 5;
	else
		return -1;


int 
handshake(s)
	int s
CODE:
	if (s)
	return 0;
	
int 
do_net_open(interface)
	char * interface
CODE:
	int s, port;
	char ip[16];
	SOCKADDR_IN s_in;

	port = get_ip_port(interface, ip, sizeof(ip) - 1);
	if (port == -1) return -1;

	memset(&s_in, 0, sizeof(SOCKADDR_IN *));
	s_in.sin_family = PF_INET;
	s_in.sin_port = htons(port);
	if (!inet_aton(ip, &s_in.sin_addr)) return -1;
	if ((s = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;
	printf("Connecting to %s port %d...\n", ip, port);

	if (connect(s, (struct sockaddr *) &s_in, sizeof(s_in)) == -1)
	{
		close(s);
		printf("Failed to connect\n");
		return -1;
	}
	if (handshake(s) == -1)
	{
		close(s);

		printf("Failed to connect - handshake failed\n");

		return -1;
	}
	printf("Connection successful\n");
RETVAL = s;
OUTPUT:
	RETVAL

void 
queue_add(head, q)
	NETQUEUE * head
	NETQUEUE * q
CODE:
	NETQUEUE * pos = head->q_prev;
	q->q_prev = pos;
	q->q_next = pos->q_next;
	q->q_next->q_prev = q;
	pos->q_next = q;
		
void 
queue_del(q)
	NETQUEUE * q
CODE:
	q->q_prev->q_next = q->q_next;
	q->q_next->q_prev = q->q_prev;

int 
queue_get(pn, buf, len)
	PRIVATE_NET * pn
	void * buf
	int len
CODE:
	NETQUEUE * head = &pn->pn_queue;
	NETQUEUE * q = head->q_next;
	if (q == head) return 0;
	assert(q->q_len <= len);
	memcpy(buf, q->q_buf, q->q_len);
	queue_del(q);
	queue_add(&pn->pn_queue_free, q);
	return q->q_len;


int 
net_write(wi, ts, dlt, h80211, len, ti)
	WIF * wi
	TIME * ts
	int dlt
	unsigned char * h80211
	int len
	Tx * ti
CODE:
	PRIVATE_NET * pn = wi_priv(wi);
	int sz = sizeof(*ti);
	unsigned char buf[2048];
	unsigned char * ptr = buf;
	(void) ts;
	(void) dlt;
	if (ti)
		memcpy(ptr, ti, sz); 
	else
		memset(ptr, 0, sizeof(*ti)); 
	ptr += sz;
	memcpy(ptr, h80211, len);
	sz += len;
	return net_cmd(pn, NET_WRITE, buf, sz);

int 
net_set_channel(wi, channel)
	WIF *wi
	int channel
CODE:
	uint32_t c = htonl(channel);
	return net_cmd(wi_priv(wi), NET_SET_CHAN, &c, sizeof(c));


int 
net_get_channel(wi)
	WIF * wi
CODE:
	PRIVATE_NET * pn = wi_priv(wi);
	return net_cmd(pn, NET_GET_CHAN, NULL, 0);

int 
net_set_rate(wi, rate)
	WIF *wi
	int rate
CODE:
	uint32_t c = htonl(rate);
	return net_cmd(wi_priv(wi), NET_SET_RATE, &c, sizeof(c));


int 
net_get_rate(wi)
	WIF * wi
CODE:
	PRIVATE_NET * pn = wi_priv(wi);
	return net_cmd(pn, NET_GET_RATE, NULL, 0);


int 
net_get_monitor(wi)
	WIF *wi
CODE:
	return net_cmd(wi_priv(wi), NET_GET_MONITOR, NULL, 0);




int 
net_read(wi, ts, dlt, h80211, len, ri)
	WIF * wi
	TIME * ts
	int * dlt
	unsigned char * h80211
	int len
	Rx * ri
CODE:
	PRIVATE_NET * pn = wi_priv(wi);
	uint32_t buf[512] = {0};
	unsigned char * bufc = (unsigned char *) buf;
	int cmd;
	int sz = sizeof(*ri);
	int l;
	int ret;
	l = queue_get(pn, buf, sizeof(buf));
	if (!l)
	{
		l = sizeof(buf);
		cmd = net_get(pn->pn_s, buf, &l);

		if (cmd == -1) return -1;
		if (cmd == NET_RC)
		{
			ret = ntohl((buf[0]));
			return ret;
		}
		assert(cmd == NET_PACKET);
	}
	if (ri)
	{
		uint64_t hi = buf[0];
		ri->ri_mactime = __be64_to_cpu(((hi) << 32U) | buf[1]);
		ri->ri_power = __be32_to_cpu(buf[2]);
		ri->ri_noise = __be32_to_cpu(buf[3]);
		ri->ri_channel = __be32_to_cpu(buf[4]);
		ri->ri_freq = __be32_to_cpu(buf[5]);
		ri->ri_rate = __be32_to_cpu(buf[6]);
		ri->ri_antenna = __be32_to_cpu(buf[7]);
	}
	l -= sz;
	assert(l > 0);
	if (l > len) l = len;
	memcpy(h80211, &bufc[sz], l);

	if (dlt)
	{
		*dlt = LINKTYPE_IEEE802_11;
	}

	if (ts)
	{
		clock_gettime(CLOCK_REALTIME, ts);
	}

	return l;
		
WIF * 
net_open(interface)
	char * interface
#CODE:
#	WIF *wi;
#	PRIVATE_NET * pn;
#	int s;
#	wi = wi_alloc(sizeof(*pn));
#	wi->wi_read = net_read;
#	wi->wi_write = net_write;
#	wi->wi_set_channel = net_set_channel;
#	wi->wi_get_channel = net_get_channel;
#	wi->wi_set_rate = net_set_rate;
#	wi->wi_get_rate = net_get_rate;
#	wi->wi_close = net_close;
#	wi->wi_fd = net_fd;
#	wi->wi_get_mac = net_get_mac;
#	wi->wi_get_monitor = net_get_monitor;
#
#	s = do_net_open(interface);
#	pn = wi_priv(wi);
#	pn->pn_s = s;
#	pn->pn_queue->q_next = pn->pn_queue->q_prev = &pn->pn_queue;
#	pn->pn_queue_free->q_next = pn->pn_queue_free->q_prev = &pn->pn_queue_free;
#	RETVAL = wi;
#OUTPUT:
#RETVAL

int
net_read_exact(s, argoument,  length)
	int s
	void *argoument
	int length


NETQUEUE * 
queue_get_slot(pn)
	PRIVATE_NET * pn
CODE:

	NETQUEUE * q = pn->pn_queue_free->q_next;
	if (pn->pn_queue_len++ > QUEUE_MAX) return NULL;
	return malloc(sizeof(*q));
	
void 
net_enque(pn, buf, len)
	PRIVATE_NET * pn
	void * buf
	int len
CODE:
	NETQUEUE * q;
	q = queue_get_slot(pn);
	if (!q) return;
	q->q_len = len;
	assert((int) sizeof(q->q_buf) >= q->q_len);
	memcpy(q->q_buf, buf, q->q_len);
	queue_add(&pn->pn_queue, q);


int 
net_get_nopacket(pn, arg, len)
	PRIVATE_NET *pn
	void *arg
	int *len
CODE:
	unsigned char buf[2048];
	int l = sizeof(buf);
	int c;
	while (1)
	{
		l = sizeof(buf);
		c = net_get(pn->pn_s, buf, &l);
		if (c < 0) return c;

		if (c != NET_PACKET && c > 0) break;

		if (c > 0) net_enque(pn, buf, l);
	}

	assert(l <= *len);
	memcpy(arg, buf, l);
	*len = l;
	return c;
	
int
net_send(s, command, argoument, length)
	int s
	int command
	void *argoument
	int length

int 
net_cmd(pn, command, arg, alen)
	PRIVATE_NET * pn
	int command
	void * arg
	int alen
CODE:
	uint32_t rc = 0;
	int len;
	int cmd;

	if (net_send(pn->pn_s, command, arg, alen) == -1)
	{
		return -1;
	}

	len = sizeof(rc);
	cmd = net_get_nopacket(pn, &rc, &len);
	if (cmd == -1)
	{
		return -1;
	}
	assert(cmd == NET_RC);
	assert(len == sizeof(rc));
	RETVAL = ntohl(rc);
OUTPUT:
RETVAL



int
net_get(s, argoument, length)
	int s
	void *argoument
	int length

WIF * 
wi_open_osdep(interface)
	char * interface
	
WIF *
file_open(interface)
	char *interface

WIF * 
wi_open(interface)
	char * interface
CODE:
	WIF * wi;
	if (interface == NULL || interface[0] == 0)
	{
		return NULL;
	}
	wi = file_open(interface);
	if (wi == (WIF *) -1) return NULL;
	if (!wi) wi = net_open(interface);
	if (!wi) wi = wi_open_osdep(interface);
	if (!wi) return NULL;

	strncpy(wi->wi_interface, interface, sizeof(wi->wi_interface) - 1);
	wi->wi_interface[sizeof(wi->wi_interface) - 1] = 0;
	return wi;


int
wi_write(wi, ts, dlt, h80211, length, ti)
	WIF * wi
	TIME * ts
	int dlt
	unsigned char * h80211
	int length
	Tx * ti
CODE:
	assert(wi->wi_write);
	return wi->wi_write(wi, ts, dlt, h80211, length, ti);

int 
wi_set_channel(wi, channel)
	WIF *wi
	int channel

int 
wi_set_ht_channel(wi, channel, htval)
	WIF * wi
	int channel
	unsigned int htval

int 
wi_get_channel(wi)
	WIF * wi

int
wi_set_freq(wi, frequency)
	WIF * wi
	int frequency

int
wi_get_freq(wi)
	WIF * wi

void
wi_close(wi)
	WIF * wi

char *
wi_get_ifname(wi)
	WIF * wi

int 
wi_get_mac(wi, mac)
	WIF * wi
	unsigned char * mac

int 
wi_set_mac(wi, mac)
	WIF *wi
	unsigned char *mac
	
int 
wi_get_rate(wi)
	WIF *wi

int 
wi_set_rate(wi, rate)
	WIF *wi
	int rate
	
int
wi_get_monitor(wi)
	WIF *wi

	
int
wi_get_mtu(wi)
	WIF *wi

int 
wi_set_mtu(wi, mtu)
	WIF *wi
	int mtu
	
void
PTW_freeattackstate(state)
	PTW_STATE *state

#int
#PTW_computeKey(PTW_attackstate *, uint8_t *, int, int, int *, int[][PTW_n], int attacks)

float
get_80211n_rate(width,  is_short_GI,  mcs_index)
	const int width
	const int is_short_GI
	const int mcs_index

float 
get_80211ac_rate(width, is_short_GI, mcs_idx, amount_ss)
	const int width   
	const int is_short_GI
	const int mcs_idx 
	const int amount_ss

int
dump_write_csv(first_ap, first_st, encryption)
	AP * first_ap
	ST * first_st
	unsigned int encryption
CODE:
	int i, probes_written;
	TM * ltime;
	AP * ap_cur;
	ST * st_cur;
	char * temp;

	if (!opt.record_data || !opt.output_format_csv) return (0);

	fseek(opt.f_txt, 0, SEEK_SET);

	fprintf(opt.f_txt,
			"\r\nBSSID, First time seen, Last time seen, channel, Speed, "
			"Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, "
			"ID-length, ESSID, Key\r\n");

	ap_cur = first_ap;

	while (ap_cur != NULL)
	{
		if (memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (ap_cur->security != 0 && encryption != 0
			&& ((ap_cur->security & encryption) == 0))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		fprintf(opt.f_txt,
				"%02X:%02X:%02X:%02X:%02X:%02X, ",
				ap_cur->bssid[0],
				ap_cur->bssid[1],
				ap_cur->bssid[2],
				ap_cur->bssid[3],
				ap_cur->bssid[4],
				ap_cur->bssid[5]);

		ltime = localtime(&ap_cur->tinit);

		fprintf(opt.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		ltime = localtime(&ap_cur->tlast);

		fprintf(opt.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		fprintf(opt.f_txt, "%2d, %3d,", ap_cur->channel, ap_cur->max_speed);

		if ((ap_cur->security
			 & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2 | AUTH_SAE | AUTH_OWE))
			== 0)
			fprintf(opt.f_txt, " ");
		else
		{
			if (ap_cur->security & STD_WPA2)
			{
				if (ap_cur->security & AUTH_SAE || ap_cur->security & AUTH_OWE)
					fprintf(opt.f_txt, " WPA3");
				fprintf(opt.f_txt, " WPA2");
			}
			if (ap_cur->security & STD_WPA) fprintf(opt.f_txt, " WPA");
			if (ap_cur->security & STD_WEP) fprintf(opt.f_txt, " WEP");
			if (ap_cur->security & STD_OPN) fprintf(opt.f_txt, " OPN");
		}

		fprintf(opt.f_txt, ",");

		if ((ap_cur->security & ENC_FIELD) == 0)
			fprintf(opt.f_txt, " ");
		else
		{
			if (ap_cur->security & ENC_CCMP) fprintf(opt.f_txt, " CCMP");
			if (ap_cur->security & ENC_WRAP) fprintf(opt.f_txt, " WRAP");
			if (ap_cur->security & ENC_TKIP) fprintf(opt.f_txt, " TKIP");
			if (ap_cur->security & ENC_WEP104) fprintf(opt.f_txt, " WEP104");
			if (ap_cur->security & ENC_WEP40) fprintf(opt.f_txt, " WEP40");
			if (ap_cur->security & ENC_WEP) fprintf(opt.f_txt, " WEP");
			if (ap_cur->security & ENC_GCMP) fprintf(opt.f_txt, " GCMP");
			if (ap_cur->security & ENC_GMAC) fprintf(opt.f_txt, " GMAC");
		}

		fprintf(opt.f_txt, ",");

		if ((ap_cur->security & AUTH_FIELD) == 0)
			fprintf(opt.f_txt, "   ");
		else
		{
			if (ap_cur->security & AUTH_SAE) fprintf(opt.f_txt, " SAE");
			if (ap_cur->security & AUTH_MGT) fprintf(opt.f_txt, " MGT");
			if (ap_cur->security & AUTH_CMAC) fprintf(opt.f_txt, " CMAC");
			if (ap_cur->security & AUTH_PSK)
			{
				if (ap_cur->security & STD_WEP)
					fprintf(opt.f_txt, " SKA");
				else
					fprintf(opt.f_txt, " PSK");
			}
			if (ap_cur->security & AUTH_OWE) fprintf(opt.f_txt, " OWE");
			if (ap_cur->security & AUTH_OPN) fprintf(opt.f_txt, " OPN");
		}

		fprintf(opt.f_txt,
				", %3d, %8lu, %8lu, ",
				ap_cur->avg_power,
				ap_cur->nb_bcn,
				ap_cur->nb_data);

		fprintf(opt.f_txt,
				"%3d.%3d.%3d.%3d, ",
				ap_cur->lanip[0],
				ap_cur->lanip[1],
				ap_cur->lanip[2],
				ap_cur->lanip[3]);

		fprintf(opt.f_txt, "%3d, ", ap_cur->ssid_length);

		if (verifyssid(ap_cur->essid))
			fprintf(opt.f_txt, "%s, ", ap_cur->essid);
		else
		{
			temp = format_text_for_csv(ap_cur->essid,
									   (size_t) ap_cur->ssid_length);
			if (temp != NULL) //-V547
			{
				fprintf(opt.f_txt, "%s, ", temp);
				free(temp);
			}
		}

		if (ap_cur->key != NULL)
		{
			for (i = 0; i < (int) strlen(ap_cur->key); i++)
			{
				fprintf(opt.f_txt, "%02X", ap_cur->key[i]);
				if (i < (int) (strlen(ap_cur->key) - 1))
					fprintf(opt.f_txt, ":");
			}
		}

		fprintf(opt.f_txt, "\r\n");

		ap_cur = ap_cur->next;
	}

	fprintf(opt.f_txt, "\r\nStation MAC, First time seen, Last time seen, " 
	"Power, # packets, BSSID, Probed ESSIDs\r\n");

	st_cur = first_st;

	while (st_cur != NULL)
	{
		ap_cur = st_cur->base;

		if (ap_cur->nb_pkt < 2)
		{
			st_cur = st_cur->next;
			continue;
		}

		fprintf(opt.f_txt,
				"%02X:%02X:%02X:%02X:%02X:%02X, ",
				st_cur->stmac[0],
				st_cur->stmac[1],
				st_cur->stmac[2],
				st_cur->stmac[3],
				st_cur->stmac[4],
				st_cur->stmac[5]);

		ltime = localtime(&st_cur->tinit);

		fprintf(opt.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		ltime = localtime(&st_cur->tlast);

		fprintf(opt.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		fprintf(opt.f_txt, "%3d, %8lu, ", st_cur->power, st_cur->nb_pkt);

		if (!memcmp(ap_cur->bssid, BROADCAST, 6))
			fprintf(opt.f_txt, "(not associated) ,");
		else
			fprintf(opt.f_txt,
					"%02X:%02X:%02X:%02X:%02X:%02X,",
					ap_cur->bssid[0],
					ap_cur->bssid[1],
					ap_cur->bssid[2],
					ap_cur->bssid[3],
					ap_cur->bssid[4],
					ap_cur->bssid[5]);

		probes_written = 0;
		for (i = 0; i < NB_PRB; i++)
		{
			if (st_cur->ssid_length[i] == 0) continue;

			if (verifyssid((const unsigned char *) st_cur->probes[i]))
			{
				temp = (char *) calloc(
					1, (st_cur->ssid_length[i] + 1) * sizeof(char));
				ALLEGE(temp != NULL);
				memcpy(temp, st_cur->probes[i], st_cur->ssid_length[i] + 1u);
			}
			else
			{
				temp = format_text_for_csv((unsigned char *) st_cur->probes[i], (size_t) st_cur->ssid_length[i]);
				ALLEGE(temp != NULL); 
			}

			if (probes_written == 0)
			{
				fprintf(opt.f_txt, "%s", temp);
				probes_written = 1;
			}
			else
			{
				fprintf(opt.f_txt, ",%s", temp);
			}

			free(temp);
		}

		fprintf(opt.f_txt, "\r\n");

		st_cur = st_cur->next;
	}

	fprintf(opt.f_txt, "\r\n");
	fflush(opt.f_txt);

	return (0);

int 
dump_write_airodump_ng_logcsv_add_ap(ap_cur, ri_power, tm_gpstime, gps_location) 
	const AP * ap_cur
	const int32_t ri_power
	TM * tm_gpstime
	float gps_location
CODE:
	if (ap_cur == NULL || !opt.output_format_log_csv || !opt.f_logcsv)
	{
		return (0);
	}
	TM * ltime = localtime(&ap_cur->tlast);
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + ltime->tm_year,
			1 + ltime->tm_mon,
			ltime->tm_mday,
			ltime->tm_hour,
			ltime->tm_min,
			ltime->tm_sec);
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + tm_gpstime->tm_year,
			1 + tm_gpstime->tm_mon,
			tm_gpstime->tm_mday,
			tm_gpstime->tm_hour,
			tm_gpstime->tm_min,
			tm_gpstime->tm_sec);

	fprintf(opt.f_logcsv, "%s,", ap_cur->essid);


	fprintf(opt.f_logcsv,
			"%02X:%02X:%02X:%02X:%02X:%02X,",
			ap_cur->bssid[0],
			ap_cur->bssid[1],
			ap_cur->bssid[2],
			ap_cur->bssid[3],
			ap_cur->bssid[4],
			ap_cur->bssid[5]);

	fprintf(opt.f_logcsv, "%d,", ri_power);

	if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) == 0)
		fputs(" ", opt.f_logcsv);
	else
	{
		if (ap_cur->security & STD_WPA2) fputs(" WPA2 ", opt.f_logcsv);
		if (ap_cur->security & STD_WPA) fputs(" WPA ", opt.f_logcsv);
		if (ap_cur->security & STD_WEP) fputs(" WEP ", opt.f_logcsv);
		if (ap_cur->security & STD_OPN) fputs(" OPN", opt.f_logcsv);
	}

	fputs(",", opt.f_logcsv);
	fprintf(opt.f_logcsv,
			"%.6f,%.6f,%.3f,%.3f,AP\r\n",
			gps_loc[0],
			gps_loc[1],
			gps_loc[5],
			gps_loc[6]);
	return (0);


int 
dump_write_airodump_ng_logcsv_add_client(ap_cur, st_cur, ri_power, tm_gpstime, gps_loc)
	AP * ap_cur
	ST * st_cur
	const int32_t ri_power
	TM * tm_gpstime
	float * gps_loc
CODE:
	if (st_cur == NULL || !opt.output_format_log_csv || !opt.f_logcsv)
	{
		return (0);
	}
	TM * ltime = localtime(&ap_cur->tlast);
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + ltime->tm_year,
			1 + ltime->tm_mon,
			ltime->tm_mday,
			ltime->tm_hour,
			ltime->tm_min,
			ltime->tm_sec);

	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + tm_gpstime->tm_year,
			1 + tm_gpstime->tm_mon,
			tm_gpstime->tm_mday,
			tm_gpstime->tm_hour,
			tm_gpstime->tm_min,
			tm_gpstime->tm_sec);

	fprintf(opt.f_logcsv, ",");
	fprintf(opt.f_logcsv,
			"%02X:%02X:%02X:%02X:%02X:%02X,",
			st_cur->stmac[0],
			st_cur->stmac[1],
			st_cur->stmac[2],
			st_cur->stmac[3],
			st_cur->stmac[4],
			st_cur->stmac[5]);

	fprintf(opt.f_logcsv, "%d,", ri_power);
	fprintf(opt.f_logcsv, ",");
	fprintf(opt.f_logcsv,
			"%.6f,%.6f,%.3f,%.3f,",
			gps_loc[0],
			gps_loc[1],
			gps_loc[5],
			gps_loc[6]);
	fprintf(opt.f_logcsv, "Client\r\n");
	return (0);
	


char *
get_manufacturer_from_string(buffer)
	char * buffer
	
int
dump_write_kismet_netxml(ap_1st,  st_1st, encryption, airodump_start_time)
	AP * ap_1st
	ST * st_1st
	unsigned int encryption
	char * airodump_start_time
		
int 
dump_write_kismet_csv( ap_1st,  st_1st, encryption)
	AP * ap_1st
	ST * st_1st
	unsigned int encryption
	

SESSION *
ac_session_new()
CODE:
	return (SESSION *) calloc(1, sizeof(SESSION));


	
int 
ac_session_destroy(s)
	SESSION *s
CODE:
	if (s == NULL || s->filename == NULL)
	{
		return (0);
	}

	ALLEGE(pthread_mutex_lock(&(s->mutex)) == 0);
	FILE * f = fopen(s->filename, "r");
	if (!f)
	{
		ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);
		return (0);
	}
	fclose(f);
	int ret = remove(s->filename);
	ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);
	return (ret == 0);

	
void 
ac_session_free(s)
	SESSION **s
CODE:
	if (s == NULL || *s == NULL)
	{
		return;
	}

	if ((*s)->filename)
	{
		struct stat scs;
		memset(&scs, 0, sizeof(struct stat));
		ALLEGE(pthread_mutex_lock(&((*s)->mutex)) == 0);
		if (stat((*s)->filename, &scs) == 0 && scs.st_size == 0)
		{
			ALLEGE(pthread_mutex_unlock(&((*s)->mutex)) == 0);
			ac_session_destroy(*s);
		}

		free((*s)->filename);
	}
	if ((*s)->argv)
	{
		for (int i = 0; i < (*s)->argc; ++i)
		{
			free((*s)->argv[i]);
		}
		free((*s)->argv);
	}
	if ((*s)->working_dir) free((*s)->working_dir);

	free(*s);
	*s = NULL;

int 
ac_session_init(s)
	SESSION *s
CODE:
	if (s == NULL)
	{
		return (EXIT_FAILURE);
	}

	memset(s, 0, sizeof(struct session));
	ALLEGE(pthread_mutex_init(&(s->mutex), NULL) == 0);
	return (EXIT_SUCCESS);

int
ac_session_set_working_directory(session, directory)
	SESSION *session
	const char *directory
CODE:
	if (session == NULL || directory == NULL || directory[0] == 0 || chdir(directory) == -1)
	{
		return (EXIT_FAILURE);
	}

	session->working_dir = strdup(directory);

	return ((session->working_dir) ? EXIT_SUCCESS : EXIT_FAILURE);

	
int 
ac_session_set_bssid( session, sbssid)
	SESSION * session
	const char *sbssid
CODE:
	if (session == NULL || sbssid == NULL || strlen(sbssid) != 17)
	{
		return (EXIT_FAILURE);
	}
	unsigned int bssid[6];
	int count = sscanf(sbssid,
					   "%02X:%02X:%02X:%02X:%02X:%02X",
					   &bssid[0],
					   &bssid[1],
					   &bssid[2],
					   &bssid[3],
					   &bssid[4],
					   &bssid[5]);
	if (count < 6)
	{
		return (EXIT_FAILURE);
	}

	for (int i = 0; i < 6; ++i)
	{
		session->bssid[i] = (uint8_t) bssid[i];
	}
	return (EXIT_SUCCESS);

int
ac_session_set_wordlist_settings(session, wordlist)
	SESSION *session
	const char * wordlist
CODE:
	if (session == NULL || wordlist == NULL)
	{
		return (EXIT_FAILURE);
	}

	int nb_input_scanned = sscanf(wordlist,
								  "%hhu %" PRId64 " %lld",
								  &(session->wordlist_id),
								  &(session->pos),
								  &(session->nb_keys_tried));

	if (nb_input_scanned != 3 || session->pos < 0 || session->nb_keys_tried < 0)
	{
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);

char *
ac_session_getline(f)
	FILE *f
CODE:
	if (f == NULL)
	{
		return (NULL);
	}
	char * ret = NULL;
	size_t n = 0;
	ssize_t line_len = getline(&ret, &n, f);
	if (line_len == -1)
	{
		return (NULL);
	}
	return (ret);


SESSION * 
ac_session_load(filename)
	const char * filename
CODE:
	int temp;
	if (filename == NULL || filename[0] == 0)
	{
		return (NULL);
	}
	FILE * f = fopen(filename, "r");
	if (f == NULL)
	{
		return (NULL);
	}

	if (fseeko(f, 0, SEEK_END))
	{
		fclose(f);
		return (NULL);
	}
	uint64_t fsize = ftello(f);
	if (fsize == 0)
	{
		fclose(f);
		return (NULL);
	}
	rewind(f);

	SESSION * ret = ac_session_new();
	if (ret == NULL)
	{
		fclose(f);
		return (NULL);
	}

	ac_session_init(ret);
	ret->is_loaded = 1;
	ret->filename = strdup(filename);
	ALLEGE(ret->filename != NULL);

	char * line;
	int line_nr = 0;
	while (1)
	{
		line = ac_session_getline(f);
		if (line == NULL) break;
		if (line[0] == '#') continue;
		rtrim(line);

		switch (line_nr)
		{
			case AC_SESSION_CWD_LINE: 
			{
				temp = ac_session_set_working_directory(ret, line);
				break;
			}
			case AC_SESSION_BSSID_LINE: 
			{
				temp = ac_session_set_bssid(ret, line);
				break;
			}
			case AC_SESSION_WL_SETTINGS_LINE: 
				{
					temp = ac_session_set_wordlist_settings(ret, line);
					break;
				}
			case AC_SESSION_ARGC_LINE: 
			{
				temp = ac_session_set_amount_arguments(ret, line);
				break;
			}
			default: 
			{
				ret->argv[line_nr - SESSION_ARGUMENTS_LINE] = line;
				temp = EXIT_SUCCESS;
				break;
			}
		}

		if (line_nr < SESSION_ARGUMENTS_LINE)
		{
			free(line);
		}

		if (temp == EXIT_FAILURE)
		{
			fclose(f);
			ac_session_free(&ret);
			return (NULL);
		}

		++line_nr;
	}

	fclose(f);
	if (line_nr < SESSION_ARGUMENTS_LINE + 1)
	{
		ac_session_free(&ret);
		return (NULL);
	}

	return (ret);




SESSION *
ac_session_from_argv(argc, argv, filename)
	const int argc
	char ** argv
	const char * filename
CODE:
	if (filename == NULL || filename[0] == 0 || argc <= 3 || argv == NULL)
	{
		return (NULL);
	}

	int fd = -1;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666)) >= 0)
	{

		close(fd);
	}
	else
	{

		fprintf(stderr, "Session file already exists: %s\n", filename);
		return (NULL);
	}


	SESSION * ret = ac_session_new();
	if (ret == NULL)
	{
		return (NULL);
	}
	ac_session_init(ret);

	ret->working_dir = get_current_working_directory();

	ret->filename = strdup(filename);
	ALLEGE(ret->filename != NULL);

	ret->argv
		= (char **) calloc(argc - AMOUNT_ARGUMENTS_IGNORE, sizeof(char *));
	ALLEGE(ret->argv != NULL);

	if (ret->working_dir == NULL)
	{
		ac_session_free(&ret);
		return (NULL);
	}

	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], filename) == 0)
		{
			ret->argc--;
			free(ret->argv[ret->argc]);
			ret->argv[ret->argc] = NULL;
			continue;
		}

		ret->argv[ret->argc] = strdup(argv[i]);
		if (ret->argv[ret->argc] == NULL)
		{
			ac_session_free(&ret);
			return (NULL);
		}

		ret->argc++;
	}

	RETVAL = (ret);
OUTPUT:
RETVAL


int
ac_session_save(s, pos, nb_keys_tried)
	SESSION *s
	uint64_t pos
	long long int nb_keys_tried
CODE:
	if (s == NULL || s->filename == NULL || s->working_dir == NULL
		|| s->argc == 0
		|| s->argv == NULL)
	{
		return (-1);
	}

	s->nb_keys_tried = nb_keys_tried;
	ALLEGE(pthread_mutex_lock(&(s->mutex)) == 0);
	FILE * f = fopen(s->filename, "w");
	if (f == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);
		return (-1);
	}
	s->pos = pos;
	fprintf(f, "%s\n", s->working_dir);
	fprintf(f,
			"%02X:%02X:%02X:%02X:%02X:%02X\n",
			s->bssid[0],
			s->bssid[1],
			s->bssid[2],
			s->bssid[3],
			s->bssid[4],
			s->bssid[5]);
	fprintf(
		f, "%d %" PRId64 " %lld\n", s->wordlist_id, s->pos, s->nb_keys_tried);
	fprintf(f, "%d\n", s->argc);
	for (int i = 0; i < s->argc; ++i)
	{
		fprintf(f, "%s\n", s->argv[i]);
	}
	fclose(f);
	ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);
	return (0);


int
getBits(b, from,length)
	unsigned char b
	int from
	int length

FILE *
init_new_pcap(filename)
	const char * filename
CODE:
	REQUIRE(filename != NULL);

	FILE * f;
	f = openfile(filename, "wb", 1);
	if (f != NULL)
	{
		if (fwrite(&_pfh_out, 1, sizeof(_pfh_out), f)
			!= (size_t) sizeof(_pfh_out))
		{
			perror("fwrite(pcap file header) failed");
		}
	}

	RETVAL = f;
OUTPUT:
	RETVAL


FILE * 
open_existing_pcap(filename)
	const char * filename
CODE:
	REQUIRE(filename != NULL);
	FILE * f;
	size_t temp_sizet;

	f = fopen(filename, "rb");

	if (f == NULL)
	{
		perror("Unable to open pcap");
		return NULL;
	}

	temp_sizet = (size_t) sizeof(_pfh_in);

	if (fread(&_pfh_in, 1, temp_sizet, f) != temp_sizet)
	{
		perror("fread(pcap file header) failed");
		fclose(f);
		return NULL;
	}

	if (_pfh_in.magic != TCPDUMP_MAGIC && _pfh_in.magic != TCPDUMP_CIGAM)
	{
		printf("\"%s\" isn't a pcap file (expected "
			   "TCPDUMP_MAGIC).\n",
			   filename);
		fclose(f);
		return NULL;
	}
	_pfh_out = _pfh_in;

	if (_pfh_in.magic == TCPDUMP_CIGAM) SWAP32(_pfh_in.linktype);

	if (_pfh_in.linktype != LINKTYPE_IEEE802_11
		&& _pfh_in.linktype != LINKTYPE_PRISM_HEADER
		&& _pfh_in.linktype != LINKTYPE_RADIOTAP_HDR
		&& _pfh_in.linktype != LINKTYPE_PPI_HDR)
	{
		printf("\"%s\" isn't a regular 802.11 "
			   "(wireless) capture.\n",
			   filename);
		fclose(f);
		return NULL;
	}
	else if (_pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
	{
		printf("Radiotap header found. Parsing Radiotap is experimental.\n");
	}
	else if (_pfh_in.linktype == LINKTYPE_PPI_HDR)
	{
		printf("PPI not yet supported\n");
		fclose(f);
		return NULL;
	}
	RETVAL = f;
OUTPUT:
	RETVAL
	

FILE *
openfile(filename, mode, fatal)
	const char * filename
	const char * mode
	int fatal

BOOLEAN
write_packet(file, packet)
	FILE * file
	PACKET_ELT * packet

FILE *
init_new_pcap(filename)
	const char * filename

FILE *
open_existing_pcap(filename)
	const char * filename
	
BOOLEAN
read_packets()

BOOLEAN
initialize_linked_list()

BOOLEAN
add_node_if_not_complete()

void
set_node_complete()

void
remove_last_uncomplete_node()


BOOLEAN
reset_current_packet_pointer_to_client_packet()

BOOLEAN
next_packet_pointer()


BOOLEAN
next_packet_pointer_from_client()

int
compare_SN_to_current_packet(packet)
	PACKET_ELT *packet
	
BOOLEAN
current_packet_pointer_same_fromToDS_and_source(packet)
	PACKET_ELT * packet
	
BOOLEAN
next_packet_pointer_same_fromToDS_and_source(packet)
	PACKET_ELT *packet
	
BOOLEAN 
next_packet_pointer_same_fromToDS_and_source_as_current()


BOOLEAN 
write_packets()

BOOLEAN
print_statistics()
	

	
void 
reset_current_packet_pointer()


BOOLEAN 
reset_current_packet_pointer_to_ap_packet()
CODE:
	reset_current_packet_pointer();
	return next_packet_pointer_from_ap();
	

void 
md5cryptsse(buf, salt, out, md5_type)
	unsigned char * buf
	unsigned char * salt
	char * out
	unsigned int md5_type

void 
md5_reverse(hash)
	uint32_t * hash

void 
md5_unreverse(hash)
	uint32_t * hash

void 
md4_reverse(hash)
	uint32_t * hash

void 
md4_unreverse(hash)
	uint32_t * hash

void
sha1_reverse(hash)
	uint32_t * hash

	
void
sha1_unreverse(hash)
	uint32_t * hash
	

void 
sha224_reverse(hash)
	uint32_t * hash
	
void
sha224_unreverse(hash)
	uint32_t * hash
	
void
sha256_reverse(hash)
	uint32_t * hash
	
void
sha256_unreverse()


#void
#sha384_reverse(hash)
#	ARCH_WORD_64 * hash

#void
#sha384_unreverse(hash)
#	ARCH_WORD_64 * hash

#void 
#sha512_reverse(hash)
#	ARCH_WORD_64 * hash

void 
sha512_unreverse()

#int 
#init_wpapsk(engine, wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED], nparallel, thread)
	#AC_CRYPTO *engine
	#const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED
	#int nparallel
	#int thread
	
void 
dump_text(in, length)
	void *in
	int length

void 
dump_stuff(x, size)
	void *x
	unsigned int size
	
void
dump_stuff_msg(message, x,  size)
	const void *message
	void *x
	unsigned int size
