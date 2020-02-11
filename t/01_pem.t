use strict;
use warnings;

use Test::More;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_pem );

## no critic

my @files = glob "$Bin/data/*/*";

foreach my $file (@files) {
    my $fh;
    my $key = do {
        local $RS = undef;
        open $fh, '<', $file or BAIL_OUT($OS_ERROR);
        <$fh>;
    };
    close $fh;

    $file =~ s/.+data/.../;

    is(key_is_pem($key), 1, $file . ' has PEM format')
      if ($file =~ /.pem(?:.enc|.pub)?$/);

    isnt(key_is_pem($key), 1, $file . ' has not PEM format')
      if ($file =~ /.der(?:.enc|.pub)/);
}

done_testing();
