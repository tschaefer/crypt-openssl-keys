use strict;
use warnings;

use Test::More;
use Test::Exception;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_rsa );

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

    is(key_is_rsa($key, 'qwe123'), 1, $file . ' is RSA')
      if ($file =~ /rsa/);

    isnt(key_is_rsa($key, 'qwe123'), 1, $file . ' is not RSA')
      if ($file !~ /rsa/);

    dies_ok(sub { key_is_rsa($key, 'bad') }, 'bad password')
      if ($file =~ /der.*.enc$/);
}

done_testing();
