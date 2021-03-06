#!perl

# Detect OS and Install deps for perl module and for Aircrack-ng
# Made by Edoardo Mantovani,2020

BEGIN{

# INSTALL AIRCRACK REQUIREMENTS

use strict;
use warnings;
use Config;
use Linux::Distribution qw(distribution_name);

print "Your Operating system is $Config{osname}\n";

sleep(1);

if( distribution_name() =~ /debian/ || distribution_name() =~ /ubuntu/){ #for debian/ubuntu
  system("sudo apt-get install build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre3-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils");
  }    
  elsif( distribution_name() =~ "fedora" || distribution_name() =~ "centos" ||  distribution_name() =~ "rhel" ){ #for Fedora/CentOS/RHEL
    system("sudo yum install libtool pkgconfig sqlite-devel autoconf automake openssl-devel libpcap-devel pcre-devel rfkill libnl3-devel gcc gcc-c++ ethtool hwloc-devel libcmocka-devel git make file expect hostapd wpa_supplicant iw usbutils tcpdump screen");
  }elsif( distribution_name() =~ "openSUSE" ){
    system("sudo zypper install autoconf automake libtool pkg-config libnl3-devel libopenssl-1_1-devel zlib-devel libpcap-devel sqlite3-devel pcre-devel hwloc-devel libcmocka-devel hostapd wpa_supplicant tcpdump screen iw gcc-c++ gcc");
  }elsif( distribution_name() =~ "Mageia" ){
    system("sudo urpmi autoconf automake libtool pkgconfig libnl3-devel libopenssl-devel zlib-devel libpcap-devel sqlite3-devel pcre-devel hwloc-devel libcmocka-devel hostapd wpa_supplicant tcpdump screen iw gcc-c++ gcc make");
  }elsif( distribution_name() =~ "Alpine"){
    system("sudo apk add gcc g++ make autoconf automake libtool libnl3-dev openssl-dev ethtool libpcap-dev cmocka-dev hostapd wpa_supplicant tcpdump screen iw pkgconf util-linux sqlite-dev pcre-dev linux-headers zlib-dev");
  
  
  }else{
    print "every dependencies accomplished!\n";
  
}		}
sub  END{
  # INSTALL PERL MODULE REQUIREMENTS  
  
  }

