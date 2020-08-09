
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "C/lib/osdep/aircrack_ng_airpcap.h"
#include "C/include/aircrack-ng/osdep/common.h"
#include "C/include/aircrack-ng/ptw/aircrack-ptw-lib.h"
#include "C/include/aircrack-ng/support/mcs_index_rates.h"

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
wi_write(wi,ts,dlt,h80211,len,ti)
	WIF * wi
	TIME * ts
	int dlt
	unsigned char * h80211
	int len
	Tx * ti

int 
wi_set_channel(wi, channel)
	WIF *wi
	int channel
int 
wi_set_ht_channel(wi, int channel, unsigned int htval)
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
wi_close(struct wif * wi)
	struct wif * wi

char *
wi_get_ifname(struct wif * wi)
	struct wif * wi

int 
wi_get_mac(struct wif * wi, unsigned char * mac)
	struct wif * wi
	unsigned char * mac

int 
wi_set_mac(struct wif * wi, unsigned char * mac)

int 
wi_get_rate(struct wif * wi)

int 
wi_set_rate(struct wif * wi, int rate)
int
wi_get_monitor(struct wif * wi)

int
wi_get_mtu(struct wif * wi)

int 
wi_set_mtu(struct wif * wi, int mtu)

void
PTW_freeattackstate(PTW_attackstate *)

int
PTW_addsession(PTW_attackstate *, uint8_t *, uint8_t *, int *, int)

int
PTW_computeKey(PTW_attackstate *, uint8_t *, int, int, int *, int[][PTW_n], int attacks)

float get_80211n_rate(const int width,
					  const int is_short_GI,
					  const int mcs_index)

float get_80211ac_rate(const int width,
					   const int is_short_GI,
					   const int mcs_idx,
					   const int amount_ss)


