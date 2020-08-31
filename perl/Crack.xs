#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "Ctxs.h"
#include <netinet/in.h>

#define SUCCESS 0
#define FAILURE 1
#define RESTART 2

#define QUEUE_MAX 666

#define NET_RC  1
#define NET_PACKET 1


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

typedef struct  {
	unsigned char q_buf[2048];
	int q_len;
	struct netqueue * q_next;
	struct netqueue * q_prev;
}netqueue;

typedef struct netqueue NETQUEUE;


typedef struct {
	int pn_s;
	NETQUEUE pn_queue;
	NETQUEUE pn_queue_free;
	int pn_queue_len;
}priv_net;
	
typedef struct priv_net PRIVATE_NET;

typedef struct packet_elt_header{
	struct packet_elt * first;
	struct packet_elt * current;
	struct packet_elt * last;
	int nb_packets;
	int average_signal; 
} * _packet_elt_head;

typedef struct  {
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

typedef struct rx_info      Rx;
typedef struct wif          WIF;
typedef struct timespec     TIME;
typedef struct timeval     TIMEVALUATE;
typedef struct AP_info      AP;
typedef struct ST_info      ST;
typedef struct tm           TM;
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
	struct netqueue * head
	struct netqueue * q
CODE:
	struct netqueue * pos = head->q_prev;
	q->q_prev = pos;
	q->q_next = pos->q_next;
	q->q_next->q_prev = q;
	pos->q_next = q;
		
void 
queue_del(q)
	struct netqueue * q
CODE:
	q->q_prev->q_next = q->q_next;
	q->q_next->q_prev = q->q_prev;

int 
queue_get(pn, buf, len)
	struct priv_net * pn
	void * buf
	int len
CODE:
	struct netqueue * head = &pn->pn_queue;
	struct netqueue * q = head->q_next;
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
	struct priv_net * pn = wi_priv(wi);
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
	struct priv_net * pn = wi_priv(wi);
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
	struct priv_net * pn = wi_priv(wi);
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
	struct priv_net * pn = wi_priv(wi);
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
CODE:
	WIF *wi;
	struct priv_net * pn;
	int s;
	wi = wi_alloc(sizeof(*pn));
	if (!wi) return NULL;
	wi->wi_read = net_read;
	wi->wi_write = net_write;
	wi->wi_set_channel = net_set_channel;
	wi->wi_get_channel = net_get_channel;
	wi->wi_set_rate = net_set_rate;
	wi->wi_get_rate = net_get_rate;
	wi->wi_close = net_close;
	wi->wi_fd = net_fd;
	wi->wi_get_mac = net_get_mac;
	wi->wi_get_monitor = net_get_monitor;

	s = do_net_open(interface);
	if (s == -1)
	{
		do_net_free(wi);
		return NULL;
	}

	pn = wi_priv(wi);
	pn->pn_s = s;
	pn->pn_queue.q_next = pn->pn_queue.q_prev = &pn->pn_queue;
	pn->pn_queue_free.q_next = pn->pn_queue_free.q_prev = &pn->pn_queue_free;
	RETVAL = wi;
OUTPUT:
RETVAL

int
net_get(s, arg, len)
	int s
	void * arg
	int * len
CODE:
	struct net_hdr nh;
	int plen;

	if (net_read_exact(s, &nh, sizeof(nh)) == -1)
	{
		return -1;
	}
	plen = ntohl(nh.nh_len);
	assert(plen <= *len && plen >= 0);

	*len = plen;
	if ((*len) && (net_read_exact(s, arg, *len) == -1))
	{
		return -1;
	}
	return nh.nh_type;
	
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
net_read_exact(s, argoument,  length)
	int s
	void *argoument
	int length

int
net_get(s, argoument, length)
	int s
	void *argoument
	int length


WIF * 
wi_open(interface)
	char * interface


int
wi_write(wi, ts, dlt, h80211, length, ti)
	WIF * wi
	TIME * ts
	int dlt
	unsigned char * h80211
	int length
	Tx * ti

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
	
int 
dump_write_airodump_ng_logcsv_add_ap(ap_cur, ri_power, tm_gpstime, gps_location) 
	const AP * ap_cur
	const int32_t ri_power
	TM * tm_gpstime
	float gps_location
	
int 
dump_write_airodump_ng_logcsv_add_client(ap_cur, st_cur, ri_power, tm_gpstime, gps_location)
	const AP * ap_cur
	const ST * st_cur
	const int32_t ri_power
	TM * tm_gpstime
	float gps_location

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

	
int 
ac_session_destroy(s)
	SESSION *s
	
void 
ac_session_free(s)
	SESSION **s
	
int 
ac_session_init(s)
	SESSION *s

int
ac_session_set_working_directory(session, directory)
	SESSION *session
	const char *directory

	
int 
ac_session_set_bssid( session, bssid)
	SESSION * session
	const char *bssid
	
int
ac_session_set_wordlist_settings(session, wordlist)
	SESSION *session
	const char * wordlist

	  
int
ac_session_set_amount_arguments(session, argouments)
	SESSION *session
	const char *argouments
	

SESSION * 
ac_session_load(filename)
	const char * filename

int
ac_session_save(s, pos, nb_keys_tried)
	SESSION *s
	uint64_t pos
	long long int nb_keys_tried
	  
SESSION *
ac_session_from_argv(argc, argv, filename)
	const int argc
	char **argv
	const char *filename
	

int
getBits(b, from,length)
	unsigned char b
	int from
	int length

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

void
reset_current_packet_pointer()


BOOLEAN
reset_current_packet_pointer_to_ap_packet()


BOOLEAN
reset_current_packet_pointer_to_client_packet()

BOOLEAN
next_packet_pointer()

BOOLEAN
next_packet_pointer_from_ap()

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
CODE:
	_packet_elt_head->current = _packet_elt_head->first;


BOOLEAN 
reset_current_packet_pointer_to_ap_packet()
CODE:
	reset_current_packet_pointer();
	return next_packet_pointer_from_ap();
	
int 
get_average_signal_ap()
CODE:
	uint32_t all_signals;
	uint32_t nb_packet_used;
	int average_signal;
	all_signals = nb_packet_used = 0;
	average_signal = -1;
	if (_pfh_in.linktype == LINKTYPE_PRISM_HEADER
		|| _pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
	{

		if (reset_current_packet_pointer_to_ap_packet() == true)
		{
			do
			{
				if (_packet_elt_head->current->version_type_subtype
						== BEACON_FRAME
					|| _packet_elt_head->current->version_type_subtype
						   == PROBE_RESPONSE)
				{
					nb_packet_used = adds_u32(nb_packet_used, 1U);
					all_signals += _packet_elt_head->current->signal_quality;
				}
			} while (next_packet_pointer_same_fromToDS_and_source(
						 _packet_elt_head->current)
					 == true);
			if (nb_packet_used > 0)
			{
				average_signal = (int) (all_signals / nb_packet_used);
				if (((all_signals / (double) nb_packet_used) - average_signal)
						* 100
					> 50)
				{
					++average_signal;
				}
			}
			printf("Average signal for AP packets: %d\n", average_signal);
		}
		else
		{
			puts("Average signal: No packets coming from the AP, cannot "
				 "calculate it");
		}
	}
	else
	{
		puts("Average signal cannot be calculated because headers does not "
			 "include it");
	}
	return average_signal;

	
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



