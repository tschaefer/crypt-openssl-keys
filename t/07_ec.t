use strict;
use warnings;

use Test::More;
use Test::Exception;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_ec );

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

    is(key_is_ec($key, 'qwe123'), 1, $file . ' is EC')
      if ($file =~ /ec/);

    isnt(key_is_ec($key, 'qwe123'), 1, $file . ' is not EC')
      if ($file !~ /ec/);

    dies_ok(sub { key_is_ec($key, 'bad') }, 'bad password')
      if ($file =~ /der.*.enc$/);
}

done_testing();
