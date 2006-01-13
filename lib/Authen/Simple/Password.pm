package Authen::Simple::Password;

use strict;
use warnings;

use Crypt::PasswdMD5 qw[];
use Digest::MD5      qw[];
use Digest::SHA      qw[];
use MIME::Base64     qw[];

sub check {
    my ( $class, $password, $encrypted ) = @_;

    return 1 if $password eq $encrypted;

    #                L   S
    # Des           13   2
    # Extended DES  20   9
    # $1$ MD5       34  12
    # $2$ Blowfish  34  16
    # $3$ NT-Hash    ?   ?

    return 1 if crypt( $password, $encrypted ) eq $encrypted;

    if ( index( $encrypted, '$1$' ) == 0 ) {
        return 1 if Crypt::PasswdMD5::unix_md5_crypt( $password, $encrypted ) eq $encrypted;
    }

    if ( index( $encrypted, '$apr1$' ) == 0 ) {
        return 1 if Crypt::PasswdMD5::apache_md5_crypt( $password, $encrypted ) eq $encrypted;
    }

    if ( index( $encrypted, '{CLEARTEXT}' ) == 0 ) {
        my $hash = substr( $encrypted, 11 );
        return 1 if $password eq $hash;
    }

    if ( index( $encrypted, '{CRYPT}' ) == 0 ) {
        my $hash = substr( $encrypted, 7 );
        return 1 if crypt( $password, $hash ) eq $hash;
    }

    if ( index( $encrypted, '{MD5}' ) == 0 ) {
        my $hash = MIME::Base64::decode( substr( $encrypted, 5 ) );
        return 1 if Digest::MD5::md5($password) eq $hash;
    }

    if ( index( $encrypted, '{SMD5}' ) == 0 ) {
        my $hash = MIME::Base64::decode( substr( $encrypted, 6 ) );
        my $salt = substr( $hash, 16 );
        return 1 if Digest::MD5::md5( $password, $salt ) . $salt eq $hash;
    }

    if ( index( $encrypted, '{SHA}' ) == 0 ) {
        my $hash = MIME::Base64::decode( substr( $encrypted, 5 ) );
        return 1 if Digest::SHA::sha1($password) eq $hash;
    }

    if ( index( $encrypted, '{SSHA}' ) == 0 ) {
        my $hash = MIME::Base64::decode( substr( $encrypted, 6 ) );
        my $salt = substr( $hash, 20 );
        return 1 if Digest::SHA::sha1( $password, $salt ) . $salt eq $hash;
    }

    # MD5
    if ( length($encrypted) == 16 ) {
        return 1 if Digest::MD5::md5($password) eq $encrypted;
    }

    if ( length($encrypted) == 22 ) {
        return 1 if Digest::MD5::md5_base64($password) eq $encrypted;
    }

    if ( length($encrypted) == 32 ) {
        return 1 if Digest::MD5::md5_hex($password) eq $encrypted;
    }

    # SHA-1
    if ( length($encrypted) == 20 ) {
        return 1 if Digest::SHA::sha1($password) eq $encrypted;
    }

    if ( length($encrypted) == 27 ) {
        return 1 if Digest::SHA::sha1_base64($password) eq $encrypted;
    }

    if ( length($encrypted) == 40 ) {
        return 1 if Digest::SHA::sha1_hex($password) eq $encrypted;
    }

    # SHA-2 224
    if ( length($encrypted) == 28 ) {
        return 1 if Digest::SHA::sha224($password) eq $encrypted;
    }

    if ( length($encrypted) == 38 ) {
        return 1 if Digest::SHA::sha224_base64($password) eq $encrypted;
    }

    if ( length($encrypted) == 56 ) {
        return 1 if Digest::SHA::sha224_hex($password) eq $encrypted;
    }

    # SHA-2 256
    if ( length($encrypted) == 32 ) {
        return 1 if Digest::SHA::sha256($password) eq $encrypted;
    }

    if ( length($encrypted) == 43 ) {
        return 1 if Digest::SHA::sha256_base64($password) eq $encrypted;
    }

    if ( length($encrypted) == 64 ) {
        return 1 if Digest::SHA::sha256_hex($password) eq $encrypted;
    }

    # SHA-2 384
    if ( length($encrypted) == 48 ) {
        return 1 if Digest::SHA::sha384($password) eq $encrypted;
    }

    if ( length($encrypted) == 64 ) {
        return 1 if Digest::SHA::sha384_base64($password) eq $encrypted;
    }

    if ( length($encrypted) == 96 ) {
        return 1 if Digest::SHA::sha384_hex($password) eq $encrypted;
    }

    # SHA-2 512
    if ( length($encrypted) == 64 ) {
        return 1 if Digest::SHA::sha512($password) eq $encrypted;
    }

    if ( length($encrypted) == 86 ) {
        return 1 if Digest::SHA::sha512_base64($password) eq $encrypted;
    }

    if ( length($encrypted) == 128 ) {
        return 1 if Digest::SHA::sha512_hex($password) eq $encrypted;
    }

    return 0;
}

1;

__END__

=head1 NAME

Authen::Simple::Password - Simple password checking

=head1 SYNOPSIS

    if ( Authen::Simple::Password->check( $password, $encrypted ) ) {
        print "Verified";
    }

=head1 DESCRIPTION

=head1 METHODS

=over 4

=item * check( $password, $encrypted )

Returns true on success and false on failure.

=back

=head1 SEE ALSO

L<Authen::Simple>

L<crypt(3)>.

=head1 AUTHOR

Christian Hansen C<ch@ngmedia.com>

=head1 COPYRIGHT

This program is free software, you can redistribute it and/or modify 
it under the same terms as Perl itself.

=cut
