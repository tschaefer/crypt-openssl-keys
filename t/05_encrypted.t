use strict;
use warnings;

use Test::More;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_encrypted );

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

    is(key_is_encrypted($key), 1, $file . ' is encrypted')
      if ($file =~ /.enc$/);

    isnt(key_is_encrypted($key), 1, $file . ' is not encrypted')
      if ($file !~ /.enc$/);
}

done_testing();
