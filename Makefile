C_AIRCRACK_DIR=perl/C
PERL_AIR_CRACK_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_AIRCRACK_DIR); make clean) && \
	(cd $(PERL_AIR_CRACK_DIR); make clean)
all: CT perlT
CT:
	(cd ./perl && chmod 755 ./install-deps.pl && perl ./install-deps.pl)
	(cd ./C && chmod 755 ./autogen.sh && ./autogen.sh && ./configure --prefix=/usr/ && make && make install)
perlT:
	(cd ./$(PERL_AIR_CRACK_DIR) && sudo perl Makefile.PL  && make && make test && make install )
