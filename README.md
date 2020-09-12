Air::Crack
==============

![image of Aircrack](./aircrack-ng.jpg)


The README is used to introduce the module and provide instructions on
how to install the module, any machine dependencies it may have (for
example C compilers and installed libraries) and any other information
that should be provided before the module is installed.

A README file is required for CPAN modules since CPAN extracts the
README file from a module distribution so that people browsing the
archive can use it get an idea of the modules uses. It is usually a
good idea to provide version information here so that people can
decide whether fixes for the module are worth downloading.

**INSTALLATION**

To install this module type the following:

```shell

   sudo make

```

Just execute the makefile script outside the C and perl directory, for now there are no tests, they will be added in future.

**DEPENDENCIES**

This library, for working properly requires the following programs:

  - [x] perl
  - [x] C compiler 
  - [x] Linux::Distribution perl library
  - [x] Config perl library
  - [x] Aircrack-ng

  
`From the Aircrack README file I report the requirements:`

 * Autoconf
 * Automake
 * Libtool
 * shtool
 * OpenSSL development package or libgcrypt development package.
 * Airmon-ng (Linux) requires ethtool, usbutils, and often pciutils.
 * On windows, cygwin has to be used and it also requires w32api package.
 * On Windows, if using clang, libiconv and libiconv-devel
 * Linux: LibNetlink 1 or 3. It can be disabled by passing --disable-libnl to configure.
 * pkg-config (pkgconf on FreeBSD)
 * FreeBSD, OpenBSD, NetBSD, Solaris and OS X with macports: gmake
 * Linux/Cygwin: make and Standard C++ Library development package (Debian: libstdc++-dev)

and the suggested libraries are:

 *   openssl
 *   Gcrypt
 *   OpenSSL
 *   Ethtool
 *   Libnl
 *   Airpcap
 *   Cmocka
 *   DUMA
 *   Hwloc
 *   Jemalloc
 *   Pcap
 *   Pcre
 *   Sqlite
 *   Tcmalloc
 *   Zlib


**Future works and directions**

This library is the result of 2 months of hard work and, still now, there are several problem related to the perl-types conversion, 
Probably the project will grow even more, my main ideas are:

- [ ] offer a full coverage for the Reaver header files
- [ ] Integrate Air::Crack with other modules, those are

   * Air::Reaver -> interface to reaver WPS library
   * Air::Pcap -> interface to airpcap library
   * Air::Lorcon2 -> interface to Lorcon2 library
   * Air::Driver -> interface for handling supported linux wireless drivers
   * Air::FakeAP -> implementation of Fluxion
   * Air::Writer -> write your own wireless driver
   * Air::Wireless -> pure perl subroutines for managing basic wireless operations
   
- [ ] Write a brief PDF manual about the six perl wireless-security module


**Aircrack-ng free RESOURCES**

this time the search for documents related to aircrack-ng was very simple, 
especially because they had an avalanche of sources in their last site, I decided to enclose a few more:

* [aircrack-ng official documentation](https://www.aircrack-ng.org/documentation.html)
* [aircrack-ng official tutorials](https://www.aircrack-ng.org/doku.php?id=tutorial)
* [aircrack-ng official book](http://www2.aircrack-ng.org/hiexpo/aircrack-ng_book_v1.pdf)
* [Penetration Testing of Wireless Networks from (KUJSS)](https://www.iasj.net/iasj?func=fulltext&aId=124737)
* [WPA Exploitation In The World Of Wireless Network](http://ijarcet.org/wp-content/uploads/IJARCET-VOL-1-ISSUE-4-609-618.pdf)
* [brief mitm tutorial with aircrack-ng and wireshark](https://dl.packetstormsecurity.net/papers/wireless/wificapture.pdf)
* [WEP traffic forgery](http://sweet.ua.pt/andre.zuquete/Aulas/SAR/13-14/docs/g8-WEP.pdf)

**Aircrack-ng Books**

Aircrack-ng has been nominated in a ton of books, in this list I'll show some of the best:

* _Rtfm: Red Team Field Manual_
* _Penetration Testing: Communication Media Testing (EC-Council Certified Security Analyst (ECSA))_
* _Wi-Foo: The Secrets of Wireless Hacking_ (2020 version seems really valid)


**COPYRIGHT AND LICENCE**

Copyright (C) 2020 by *Edoardo Mantovani*, aka BASEBAND

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.



