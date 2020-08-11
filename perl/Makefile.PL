BEGIN{

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME => 'Air::Crack',
   LICENSE => 'perl',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Crack.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -llaircrack'],
   INC => '-I/include -I/usr/include -I/usr/local/include',
   MIN_PERL_VERSION => '5.22.1',
   PREREQ_PM => {
  },
);


}
