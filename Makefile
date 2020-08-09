C_AIRCRACK_DIR=perl/C
PERL_AIR_CRACK_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_AIRCRACK_DIR); make clean) && \
	(cd $(PERL_AIR_CRACK_DIR); make clean)
all: CT perlT
CT:
	(cd ./perl/C && chmod 755 ./autogen.sh && ./autogen.sh && make)
perlT:
	(cd ./$(PERL_AIR_CRACK_DIR) && sudo perl Makefile.PL  && make && make test && make install )
