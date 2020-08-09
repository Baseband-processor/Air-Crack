C_AIRCRACK_DIR=C
PERL_AIR_CRACK_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_AIRCRACK_DIR); make clean) && \
	(cd $(PERL_AIR_CRACK_DIR); make clean)
all: CT perlT
CT:
	(cd ./C && chmod 755 ./autogen.sh && ./configure  --prefix=$(TMP_INSTALL_DIR)) && make all && make install)
perlT:
	(cd ./$(PERL_AIR_CRACK_DIR) && sudo perl Makefile.PL  && make && make install )
