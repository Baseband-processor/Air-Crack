
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "C/lib/osdep/aircrack_ng_airpcap.h"
#include "C/include/aircrack-ng/osdep/common.h"
#include "C/include/aircrack-ng/ptw/aircrack-ptw-lib.h"
#include "C/include/aircrack-ng/support/mcs_index_rates.h"

typedef PTW_attackstate  PTW_STATE;
typedef struct wif  WIF;
typedef struct timespec TIME;
typedef struct rx_info  Rx;
typedef struct tx_info  Tx;

MODULE = Air::Crack   PACKAGE = Air::Crack
PROTOTYPES: DISABLE
 
void 
airpcap_close(nl)
	void nl

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
	const int width,
	const int is_short_GI,
	const int mcs_index

float 
get_80211ac_rate(width, is_short_GI, mcs_idx, amount_ss)
	const int width,   
	const int is_short_GI,
	const int mcs_idx, 
	const int amount_ss

int dump_write_csv(struct AP_info * ap_1st,
				   struct ST_info * st_1st,
				   unsigned int f_encrypt);
int dump_write_airodump_ng_logcsv_add_ap(const struct AP_info * ap_cur,
										 const int32_t ri_power,
										 struct tm * tm_gpstime,
										 float * gps_loc);
int dump_write_airodump_ng_logcsv_add_client(const struct AP_info * ap_cur,
											 const struct ST_info * st_cur,
											 const int32_t ri_power,
											 struct tm * tm_gpstime,
											 float * gps_loc);
char * get_manufacturer_from_string(char * buffer);
int dump_write_kismet_netxml(struct AP_info * ap_1st,
							 struct ST_info * st_1st,
							 unsigned int f_encrypt,
							 char * airodump_start_time);
int dump_write_kismet_csv(struct AP_info * ap_1st,
						  struct ST_info * st_1st,
						  unsigned int f_encrypt);


struct session * ac_session_new(void);
int ac_session_destroy(struct session * s);
void ac_session_free(struct session ** s);
int ac_session_init(struct session * s);

// Validate and set the different values in the session structure
int ac_session_set_working_directory(struct session * session,
									 const char * str);
int ac_session_set_bssid(struct session * session, const char * str);
int ac_session_set_wordlist_settings(struct session * session,
									 const char * str);
int ac_session_set_amount_arguments(struct session * session, const char * str);

// Load from file
struct session * ac_session_load(const char * filename);

// Save to file
int ac_session_save(struct session * s,
					uint64_t pos,
					long long int nb_keys_tried);

struct session *
ac_session_from_argv(const int argc, char ** argv, const char * filename);

static void usage(void);
static int getBits(unsigned char b, int from, int length);
static FILE * openfile(const char * filename, const char * mode, int fatal);
static BOOLEAN write_packet(FILE * file, struct packet_elt * packet);
static FILE * init_new_pcap(const char * filename);
static FILE * open_existing_pcap(const char * filename);
static BOOLEAN read_packets(void);
static BOOLEAN initialize_linked_list(void);
static BOOLEAN add_node_if_not_complete(void);
static void set_node_complete(void);
static void remove_last_uncomplete_node(void);
static void reset_current_packet_pointer(void);
static BOOLEAN reset_current_packet_pointer_to_ap_packet(void);
static BOOLEAN reset_current_packet_pointer_to_client_packet(void);
static BOOLEAN next_packet_pointer(void);
static BOOLEAN next_packet_pointer_from_ap(void);
static BOOLEAN next_packet_pointer_from_client(void);
static int compare_SN_to_current_packet(struct packet_elt * packet);
static BOOLEAN
current_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet);
static BOOLEAN
next_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet);
static BOOLEAN next_packet_pointer_same_fromToDS_and_source_as_current(void);
static BOOLEAN write_packets(void);
static BOOLEAN print_statistics(void);
static char * status_format(int status);
static int get_average_signal_ap(void);

void md5cryptsse(unsigned char * buf,
				 unsigned char * salt,
				 char * out,
				 unsigned int md5_type)
void SIMDmd5body(vtype * data,
				 ARCH_WORD_32 * out,
				 ARCH_WORD_32 * reload_state,
				 unsigned SSEi_flags)
void md5_reverse(uint32_t * hash)
void md5_unreverse(uint32_t * hash)

void SIMDmd4body(vtype * data,
				 ARCH_WORD_32 * out,
				 ARCH_WORD_32 * reload_state,
				 unsigned SSEi_flags)
void md4_reverse(uint32_t * hash)
void md4_unreverse(uint32_t * hash)

#ifdef SIMD_PARA_SHA1
void SIMDSHA1body(vtype * data,
				  ARCH_WORD_32 * out,
				  ARCH_WORD_32 * reload_state,
				  unsigned SSEi_flags)
void sha1_reverse(uint32_t * hash)
void sha1_unreverse(uint32_t * hash)
void SIMDSHA256body(vtype * data,
					ARCH_WORD_32 * out,
					ARCH_WORD_32 * reload_state,
					unsigned SSEi_flags)
void sha224_reverse(uint32_t * hash)
void sha224_unreverse(uint32_t * hash)
void sha256_reverse(uint32_t * hash)
void sha256_unreverse(void)
#endif

#ifdef SIMD_COEF_64
#define SHA512_ALGORITHM_NAME BITS " " SIMD_TYPE " " SHA512_N_STR
void SIMDSHA512body(vtype * data,
					ARCH_WORD_64 * out,
					ARCH_WORD_64 * reload_state,
					unsigned SSEi_flags)
void sha384_reverse(ARCH_WORD_64 * hash)
void sha384_unreverse(ARCH_WORD_64 * hash)
void sha512_reverse(ARCH_WORD_64 * hash)
void sha512_unreverse(void)
void init_atoi(void)

int init_wpapsk(ac_crypto_engine_t * engine,
				const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
				int nparallel,
				int threadid)


void dump_text(void * in, int len)
void dump_stuff(void * x, unsigned int size)
void dump_stuff_msg(const void * msg, void * x, unsigned int size)
