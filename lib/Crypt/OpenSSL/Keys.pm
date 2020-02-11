package Crypt::OpenSSL::Keys;

use strict;
use warnings;

use Readonly;

use Exporter 'import';

Readonly::Array our @EXPORT_OK => qw(
  key_is_der
  key_is_dsa
  key_is_ec
  key_is_encrypted
  key_is_pem
  key_is_pkcs8
  key_is_private
  key_is_public
  key_is_rsa
  key_is_valid
);

Readonly::Hash our %EXPORT_TAGS => ( all => [@EXPORT_OK], );

our $VERSION = '0.01';

require XSLoader;
XSLoader::load( 'Crypt::OpenSSL::Keys', $VERSION );

Readonly::Scalar my $KEY_FORMAT_DER => 0;
Readonly::Scalar my $KEY_FORMAT_PEM => 1;

use Carp qw(croak);
use Try::Tiny;

no warnings "uninitialized";

sub key_is_pem {
    my $key = shift;

    return 1
      if ( $key =~ /^\s*-----BEGIN (.+)? ?(PUBLIC|PRIVATE) KEY-----/
        && $key =~ /-----END ($1)($2) KEY-----\s*$/ );

    return 0;
}

sub key_is_der {
    my $key = shift;

    return 1 if ( $key =~ /^\x30.{1,3}[\x01\x02\x20\x30]/ );

    return 0;
}

sub key_is_valid {
    my $key = shift;

    return 1 if ( key_is_pem($key) );
    return 1 if ( key_is_der($key) );

    return 0;
}

sub key_is_public {
    my $key = shift;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    if ( key_is_pem($key) ) {
        return 1 if ( $key =~ /^\s*-----BEGIN PUBLIC KEY-----/ );
    }

    if ( key_is_der($key) ) {
        my $pem = try {
            _key_xs_convert_public_der_to_pem($key);
        };
        return 1 if ($pem);
    }

    return 0;
}

sub key_is_private {
    my $key = shift;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    if ( key_is_pem($key) ) {
        return 1 if ( $key =~ /^\s*-----BEGIN .* ?PRIVATE KEY-----/ );
    }

    if ( key_is_der($key) ) {
        return 1 if ( !key_is_public($key) );
    }

    return 0;
}

sub key_is_encrypted {
    my $key = shift;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    return 0 if ( key_is_public($key) );

    if ( key_is_pem($key) ) {
        return 1 if ( $key =~ /^\s*-----BEGIN ENCRYPTED PRIVATE KEY-----/ );
        return 1 if ( $key =~ /Proc-Type: 4,ENCRYPTED/ );
    }

    if ( key_is_der($key) ) {
        my $pem = try {
            return _key_xs_convert_private_pkcs8_der_to_pem($key);
        };
        return 0 if ($pem);

        $pem = try {
            return _key_xs_convert_private_der_to_pem($key);
        };
        return 1 if ( !$pem );
    }

    return 0;
}

sub key_is_rsa {
    my ( $key, $password ) = @_;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    if ( key_is_pem($key) ) {
        if ( $key =~ /^\s*-----BEGIN (DSA|EC|RSA) PRIVATE KEY-----/ ) {
            return 1 if ( $1 =~ /RSA/ );
            return 0;
        }
        if ( key_is_public($key) ) {
            return 1 if ( _key_xs_is_public_rsa($key) );
            return 0;
        }
        if ( $key =~ /^\s*-----BEGIN PRIVATE KEY-----/ ) {
            return 1 if ( _key_xs_is_private_pkcs8_rsa($key) );
            return 0;
        }

        croak('Password missing.') if ( !$password );

        my $pem;
        $pem = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_PEM );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return key_is_rsa( $pem, $password ) if ($pem);
    }

    if ( key_is_der($key) ) {
        my $pem;

        $pem = try {
            return _key_xs_convert_public_der_to_pem($key);
        };
        return key_is_rsa( $pem, $password ) if ($pem);

        $pem = try {
            return _key_xs_convert_private_pkcs8_der_to_pem($key);
        };
        return key_is_rsa( $pem, $password ) if ($pem);

        try {
            $pem = _key_xs_convert_private_der_to_pem($key);
        };
        return key_is_rsa( $pem, $password ) if ($pem);

        croak('Password missing.') if ( !$password );

        my $der;

        $der = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_DER );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return key_is_rsa( $der, $password ) if ($der);
    }

    return 0;
}

sub key_is_ec {
    my ( $key, $password ) = @_;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    if ( key_is_pem($key) ) {
        if ( $key =~ /^\s*-----BEGIN (DSA|EC|RSA) PRIVATE KEY-----/ ) {
            return 1 if ( $1 =~ /EC/ );
            return 0;
        }
        if ( key_is_public($key) ) {
            return 1 if ( _key_xs_is_public_ec($key) );
            return 0;
        }
        if ( $key =~ /^\s*-----BEGIN PRIVATE KEY-----/ ) {
            return 1 if ( _key_xs_is_private_pkcs8_ec($key) );
            return 0;
        }

        croak('Password missing.') if ( !$password );

        my $pem;
        $pem = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_PEM );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return key_is_ec($pem) if ($pem);
    }

    if ( key_is_der($key) ) {
        my $pem;

        $pem = try {
            return _key_xs_convert_public_der_to_pem($key);
        };
        return key_is_ec($pem) if ($pem);

        $pem = try {
            return _key_xs_convert_private_pkcs8_der_to_pem($key);
        };
        return key_is_ec($pem) if ($pem);

        $pem = try {
            return _key_xs_convert_private_der_to_pem($key);
        };
        return key_is_ec($pem) if ($pem);

        croak('Missing password.') if ( !$password );

        my $der;

        $der = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_DER );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return key_is_ec($der) if ($der);
    }

    return 0;
}

sub key_is_dsa {
    my ( $key, $password ) = @_;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    if ( key_is_pem($key) ) {
        if ( $key =~ /^\s*-----BEGIN (DSA|EC|RSA) PRIVATE KEY-----/ ) {
            return 1 if ( $1 =~ /DSA/ );
            return 0;
        }
        if ( key_is_public($key) ) {
            return 1 if ( _key_xs_is_public_dsa($key) );
            return 0;
        }
        if ( $key =~ /^\s*-----BEGIN PRIVATE KEY-----/ ) {
            return 1 if ( _key_xs_is_private_pkcs8_dsa($key) );
            return 0;
        }

        croak('Password missing.') if ( !$password );

        my $pem;
        $pem = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_PEM );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return key_is_dsa($pem) if ($pem);
    }

    if ( key_is_der($key) ) {
        my $pem;

        $pem = try {
            return _key_xs_convert_public_der_to_pem($key);
        };
        return key_is_dsa($pem) if ($pem);

        $pem = try {
            return _key_xs_convert_private_pkcs8_der_to_pem($key);
        };
        return key_is_dsa($pem) if ($pem);

        $pem = try {
            return _key_xs_convert_private_der_to_pem($key);
        };
        return key_is_dsa($pem) if ($pem);

        croak('Key is encrypted and missing password.') if ( !$password );

        my $der;

        $der = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_DER );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return key_is_dsa($der) if ($der);
    }

    return 0;
}

sub key_is_pkcs8 {
    my ( $key, $password ) = @_;

    croak('Key has invalid format.') if ( !key_is_valid($key) );

    if ( key_is_pem($key) ) {
        return 1
          if ( $key =~ /^\s*-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/ );
    }

    if ( key_is_der($key) ) {
        return 0 if ( key_is_public($key) );

        my $is = try {
            return _key_xs_convert_private_pkcs8_der_to_pem($key);
        };
        return 1 if ($is);

        $is = try {
            return _key_xs_decrypt_private_pkcs8( $key, $password,
                $KEY_FORMAT_DER );
        }
        catch {
            croak('Bad password') if ( $_ =~ /bad decrypt/ );
        };
        return 1 if ($is);
    }

    return 0;
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

Crypt::OpenSSL::Keys - OpenSSL key tools.

=head1 SYNOPSIS

    use Crypt::OpenSSL::Keys qw( key_is_pem key_is_ec )

    my $file = "/run/user/1000/tmp/keys/rsa/1024.pem";

    my $fh;
    my $key = do {
        local $RS = undef;
        open $fh, '<', $file;
        <$fh>;
    };
    close $fh;

    printf("Key has Privacy Enhanced Mail (PEM) format.\n")
      if (key_is_pem($key));
    printf("Key has Rivest-Shamir-Adleman (RSA) algorithm.\n")
      if (key_is_rsa($key));

=head1 DESCRIPTION

Crypt::OpenSSL::Keys provides functionality to determine information about
crypto keys. The module is based on L<OpenSSL|https://www.openssl.org/>.

=over 2

=item *

Format (PEM, DER)

=item *

Algorithm (RSA, DSA, EC)

=item *

Encryption (true, false)

=item *

Type (public, private)

=back

=head1 METHODS

=head2 key_is_der

Verify key has Distinguished Encoding Rules (DER) format.

=head2 key_is_dsa

Verify key has Digital Signature Algorithm (DSA).

=head2 key_is_ec

Verify key has Elliptic Curve (EC) algorithm.

=head2 key_is_encrypted

Verify key is encrypted.

=head2 key_is_pem

Verify key has Privacy Enhanced Mail (PEM) format.

=head2 key_is_pkcs8

Verify key has Public-Key Cryptography Standard #8 (PKCS8).

=head2 key_is_private

Verifiy key is private.

=head2 key_is_public

Verify key is public.

=head2 key_is_rsa

Verify key has Rivest-Shamir-Adleman (RSA) algorithm.

=head2 key_is_valid

Verify key has PEM or DER format.

=head1 AUTHORS

Tobias Schäfer L<github@blackox.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2020 by Tobias Schäfer.

This is free software; you can redistribute it and/or modify it under the same
terms as the Perl 5 programming language system itself.

=cut
