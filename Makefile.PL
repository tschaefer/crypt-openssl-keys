use ExtUtils::MakeMaker;

WriteMakefile(
    'ABSTRACT'   => 'OpenSSL key tools.',
    'AUTHOR'     => 'Tobias Schaefer <github@blackox.org>',
    'DISTNAME'   => 'Crypt-OpenSSL-Keys',
    'EXE_FILES'  => [ 'bin/crypt-key-info' ],
    'META_MERGE' => {
        resources => {
            'license'    => 'http://dev.perl.org/licenses',
            'homepage'   => 'https://github.com/tschaefer/crypt-openssl-keys',
            'repository' => 'https://github.com/tschaefer/crypt-openssl-keys.git',
        }
    },
    'NAME'      => 'Crypt::OpenSSL::Keys',
    'PREREQ_PM' => {
        'Readonly'  => '>=2.05',
        'Try::Tiny' => '>=0.30',
        'Test::More' => '>=1.302171',
    },
    # https://docs.openssl.org/3.0/man7/migration_guide/#upgrading-from-openssl-111
    'CCFLAGS'      => "$Config::Config{ccflags} -Wno-deprecated-declarations",
    'DEFINE'       => '-DPERL5 -DOPENSSL_NO_KRB5',
    'LIBS'         => ['-lssl -lcrypto'],
    'XSMULTI'      => 1,
    'VERSION_FROM' => 'lib/Crypt/OpenSSL/Keys.pm',
    'clean'        => { FILES => 'Crypt-OpenSSL-Keys-*' },
    'dist'         => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    ( $ExtUtils::MakeMaker::VERSION >= 6.3002 ? ( 'LICENSE' => 'perl', ) : () ),
);
