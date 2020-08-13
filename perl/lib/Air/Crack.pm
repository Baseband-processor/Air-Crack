package Air::Crack;
require  v5.22.1;

# initial release

use strict;
use warnings;

use constant  PACKET_302 => "HTTP/1.1 302 Found\r\n\
Location: https://www.google.com/?gws_rd=ssl\r\n\
Cache-Control: private\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Date: Sun, 30 Nov 2014 03:25:47 GMT\r\n\
Server: gws\r\n\
Content-Length: 231\r\n\
X-XSS-Protection: 1; mode=block\r\n\
X-Frame-Options: SAMEORIGIN\r\n\
Alternate-Protocol: 80:quic,p=0.02\r\n\
\r\n\
<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n\
<TITLE>302 Moved</TITLE></HEAD><BODY>\n\
<H1>302 Moved</H1>\n\
The document has moved\n\
<A HREF=\"https://www.google.com/?gws_rd=ssl\">here</A>.\r\n\
</BODY></HTML>\r\n";



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
      dump_write_csv
      dump_write_airodump_ng_logcsv_add_ap
      dump_write_airodump_ng_logcsv_add_client
      get_manufacturer_from_string
      dump_write_kismet_netxml
      dump_write_kismet_csv
      ac_session_new
      ac_session_destroy
      ac_session_free
      ac_session_init
      ac_session_set_working_directory
      ac_session_set_bssid
      ac_session_set_wordlist_settings
      ac_session_set_amount_arguments
      ac_session_load
      ac_session_save
      ac_session_from_argv
      getBits
      write_packets
      print_statistics
      status_format
      get_average_signal_ap
      md5cryptsse
      SIMDmd5body
      md5_reverse
      md5_unreverse
      SIMDmd4body
      md4_reverse
      md4_unreverse
      sha1_reverse
      sha1_unreverse
      sha512_unreverse
      dump_text
      dump_stuff
      dump_stuff_msg
      
    )],
   packets => [qw(
      PACKET_302
   )],
);

our @EXPORT = (
   @{ $EXPORT_TAGS{aircrack} },
   @{ $EXPORT_TAGS{packets} },

);



__PACKAGE__->bootstrap($VERSION);


1;

__END__

