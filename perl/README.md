Air::Crack
==============

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

  - perl
  - C compiler 
  - Linux::Distribution perl library
  - Config perl library
  - Aircrack

  
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



**COPYRIGHT AND LICENCE**

Copyright (C) 2020 by *Edoardo Mantovani*, aka BASEBAND

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


<img src="https://media3.giphy.com/media/ADiOs8AqeverrAuT4Q/giphy.gif" alt="drawing" width="2000"/>
