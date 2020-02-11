use strict;
use warnings;

use Test::More;
use Test::Pod;
use Test::Pod::Coverage;

use Readonly;

## no critic

require_ok('Crypt::OpenSSL::Keys');

pod_file_ok('lib/Crypt/OpenSSL/Keys.pm');

pod_coverage_ok('Crypt::OpenSSL::Keys');

Readonly::Array my @METHODS => qw(
  key_is_der
  key_is_dsa
  key_is_ec
  key_is_encrypted
  key_is_pem
  key_is_private
  key_is_public
  key_is_rsa
  key_is_valid
);

foreach my $method (@METHODS) {
  can_ok('Crypt::OpenSSL::Keys', $method);
}

done_testing;
