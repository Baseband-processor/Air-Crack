package Air::Crack;
require  v5.22.1;

# initial release

use strict;
use warnings;

our $VERSION = '0.03';
use base qw(Exporter DynaLoader);

our %EXPORT_TAGS = (
   aircrack => [qw(
      airpcap_close
      airpcap_get_mac
      airpcap_set_mac
      airpcap_sniff
      airpcap_inject
      airpcap_init
      airpcap_set_chan
      isAirpcapDevice
      getFrequencyFromChannel
      getFrequencyFromChannel
      net_open
      net_send
      net_read_exact
      net_get
      net_get
      wi_write
      wi_set_channel
      wi_set_ht_channel
      wi_get_channel
      wi_set_freq
      wi_get_freq
      wi_close
      wi_get_ifname
      wi_get_ifname
      wi_set_macv
      wi_get_rate
      wi_set_rate
      wi_get_monitor
      wi_get_mtu
      wi_set_mtu
      PTW_freeattackstate
      get_80211n_rate
      get_80211ac_rate
    )],

);

our @EXPORT = (
   @{ $EXPORT_TAGS{aircrack} },

);



__PACKAGE__->bootstrap($VERSION);


1;

__END__

