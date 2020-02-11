use strict;
use warnings;

use Test::More;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_public );

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

    isnt(key_is_public($key), 1, $file . ' is not public')
      if ($file !~ /.pub$/);

    is(key_is_public($key), 1, $file . ' is public')
      if ($file =~ /.pub$/);
}

done_testing();
