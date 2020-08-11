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
	(cd ./perl/C && chmod 755 ./autogen.sh && ./autogen.sh && make)
perlT:
	(cd ./$(PERL_AIR_CRACK_DIR) && sudo perl Makefile.PL  && make && make test && make install )
