sub BEGIN{

   `unzip C.zip`;
   do 'install-deps.pl'; # install dependencies before continuing
}

sub END{

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME => 'Air::Crack',
   LICENSE => 'perl',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Crack.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -LC/lib/osdep'],
   INC => '-I/include -I/usr/include -I/usr/local/include -I/include/aircrack-ng/ptw/ -I/include/aircrack-ng/ce-wpa -I/include/aircrack-ng/third-party -I/include/aircrack-ng/support',
   MIN_PERL_VERSION => '5.22.1',
   PREREQ_PM => {
  },
);


}
