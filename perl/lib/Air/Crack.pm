package Air::Crack;
require  v5.22.1;

use strict;
use warnings;

our $VERSION = '0.03';
use base qw(Exporter DynaLoader);



our %EXPORT_TAGS = (
   aircrack => [qw(


    )],

);

our @EXPORT = (
   @{ $EXPORT_TAGS{aircrack} },

);



__PACKAGE__->bootstrap($VERSION);


1;

__END__

