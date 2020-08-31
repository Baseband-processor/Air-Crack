#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "Ctxs.h"


#define SUCCESS 0
#define FAILURE 1
#define RESTART 2

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



typedef bool BOOLEAN;
typedef struct WPS_INFO         WPS_INFORMATION;
typedef rc4test_func            RC4TEST;
typedef struct WPA_hdsk         WPA_HANDSHAKE;
typedef struct n_channel_info   N_CHANNEL_INFO;
typedef struct ac_channel_info  AC_CHANNEL_INFO;
typedef struct PTW_tableentry   PTW_TABLEENTRY;
typedef struct PTW_session      PTW_SESSION;
typedef struct PTW_attackstate  PTW_STATE;

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
	
WIF * 
net_open(interface)
	char * interface

int
net_send(s, command, argoument, length)
	int s
	int command
	void *argoument
	int length

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
	
	
char *
status_format(status)
	int status
	
int 
get_average_signal_ap()

	
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



