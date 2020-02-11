use strict;
use warnings;

use Test::More;
use Test::Exception;

use English qw( -no_match_vars);
use FindBin qw($Bin);

use Crypt::OpenSSL::Keys qw( key_is_pkcs8 );

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

    is(key_is_pkcs8($key, 'qwe123'), 1, $file . ' is PKCS#8')
      if ($file =~ /pkcs8/);

    isnt(key_is_pkcs8($key, 'qwe123'), 1, $file . ' is not PKCS#8')
      if ($file !~ /pkcs8/);

    dies_ok(sub { key_is_pkcs8($key, 'bad') }, 'bad password')
      if ($file =~ /der.*.enc$/);
}

done_testing();
