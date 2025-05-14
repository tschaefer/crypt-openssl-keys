use strict;
use warnings;

use Test::More;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_private );

## no critic

my @files = glob "$Bin/data/*/*";

foreach my $file (@files) {
    next if ($file =~ /SM2/);

    my $fh;
    my $key = do {
        local $RS = undef;
        open $fh, '<', $file or BAIL_OUT($OS_ERROR);
        <$fh>;
    };
    close $fh;

    $file =~ s/.+data/.../;

    is(key_is_private($key), 1, $file . ' is private')
      if ($file !~ /.pub$/);

    isnt(key_is_private($key), 1, $file . ' is not private')
      if ($file =~ /.pub$/);
}

done_testing();
