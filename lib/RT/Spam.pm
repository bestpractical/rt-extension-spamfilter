# BEGIN BPS TAGGED BLOCK {{{
#
# COPYRIGHT:
#
# This software is Copyright (c) 1996-2014 Best Practical Solutions, LLC
#                                          <sales@bestpractical.com>
#
# (Except where explicitly superseded by other copyright notices)
#
#
# LICENSE:
#
# This work is made available to you under the terms of Version 2 of
# the GNU General Public License. A copy of that license should have
# been provided with this software, but in any event can be snarfed
# from www.gnu.org.
#
# This work is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 or visit their web page on the internet at
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.
#
#
# CONTRIBUTION SUBMISSION POLICY:
#
# (The following paragraph is not intended to limit the rights granted
# to you to modify and distribute this software under the terms of
# the GNU General Public License and is only of importance to you if
# you choose to contribute your changes and enhancements to the
# community by submitting them to Best Practical Solutions, LLC.)
#
# By intentionally submitting any modifications, corrections or
# derivatives to this work, or any other work intended for use with
# Request Tracker, to Best Practical Solutions, LLC, you confirm that
# you are the copyright holder for those contributions and you grant
# Best Practical Solutions,  LLC a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.
#
# END BPS TAGGED BLOCK }}}

=head1 SYNOPSIS

    use RT::Spam;

=head1 DESCRIPTION

=head1 METHODS

=cut


package RT::Spam;
use base 'RT::Record';

sub Table {'Spams'}

use strict;
use warnings;

use MIME::Base64;

sub _OverlayAccessible {
    {
        Status => { 'read' => 1, 'write' => 1 },
        Headers => { 'read' => 1, 'write' => 0 },
        Content => { 'read' => 1, 'write' => 0 },
        Creator => { 'read' => 1, 'auto'  => 1, },
        Created => { 'read' => 1, 'auto'  => 1, },
    };
}

=head2 Create

=cut

sub Create {
    my $self = shift;
    my %args = (
        id => 0,
        @_
    );

    my $headers = $args{Message}->head->as_string;
    utf8::decode( $headers ) unless utf8::is_utf8( $headers );
    my $id = $self->SUPER::Create(
        Headers => $headers,
        Content => encode_base64($args{Message}->as_string),
        Score => $args{Score},
        map { $_ => $args{$_} } qw/Queue Action Ticket/,
    );

    unless ( $id ) {
        $RT::Logger->crit( "Spam insert failed: " . $RT::Handle->dbh->errstr );
    }
    return $id;
}

=head2 GetHeader

=cut

sub GetHeader {
    my $self = shift;
    my $tag = shift;
    foreach my $line ($self->SplitHeaders) {
        next unless $line =~ /^\Q$tag\E:\s+(.*)$/si;
        return ($1);
    }
    return undef;
}

=head2 SplitHeaders

=cut

sub SplitHeaders {
    my $self = shift;
    my $headers = ( shift || $self->_Value( 'Headers' ) );
    my @headers;
    for ( split( /\n(?=[^\ \t]|\z)/, $headers ) ) {
        push @headers, $_;
    }

    return ( @headers );
}

=head2 _Value

Takes the name of a table column.
Returns its value as a string, if the user passes an ACL check

=cut

sub _Value {
    my $self  = shift;
    my $field = shift;

    #if the field is public, return it.
    if ( $self->_Accessible( $field, 'public' ) ) {
        return ( $self->__Value( $field, @_ ) );
    }

    return undef unless $self->CurrentUserHasRight( 'AdminUsers' );
    return $self->__Value( $field, @_ );
}

sub CurrentUserHasRight {
    my $self = shift;
    my $right = shift;
    return $self->CurrentUser->HasRight( Right => $right, Object => RT->System );
}

sub id {
    my $self = shift;
    return $self->_Value('id');
}
*Id = \&id;

sub Content {
    my $self = shift;
    return decode_base64($self->_Value('Content'));
}

sub MIMEEntity {
    my $self = shift;
    return $self->{MIMEEntity} if $self->{MIMEEntity};
    my $parser = RT::EmailParser->new();
    $parser->SmartParseMIMEEntityFromScalar(
        Message => $self->Content,
        Decode  => 0,
        Exact   => 1,
    );
    $self->{MIMEEntity} = $parser->Entity;
    return $self->{MIMEEntity};
}

sub From {
    my $self = shift;
    my ( $address ) = RT::Interface::Email::ParseSenderAddressFromHead( $self->MIMEEntity->head );
    return $address;
}

sub _CoreAccessible {
    {
        id =>
		{read => 1, sql_type => 4, length => 11,  is_blob => 0,  is_numeric => 1,  type => 'int(11)', default => ''},
        Content =>
		{read => 1, sql_type => -4, length => 0,  is_blob => 1,  is_numeric => 0,  type => 'longblob', default => ''},
        Headers =>
		{read => 1, sql_type => -4, length => 0,  is_blob => 1,  is_numeric => 0,  type => 'longtext', default => ''},
        Score =>
		{read => 1, sql_type => 4, length => 11,  is_blob => 0,  is_numeric => 1,  type => 'int(11)', default => '0'},
        Queue =>
		{read => 1, sql_type => 4, length => 11,  is_blob => 0,  is_numeric => 1,  type => 'int(11)', default => ''},
        Action =>
		{read => 1, sql_type => 12, length => 255,  is_blob => 0,  is_numeric => 0,  type => 'varchar(255)', default => ''},
        Ticket =>
		{read => 1, sql_type => 4, length => 11,  is_blob => 0,  is_numeric => 1,  type => 'int(11)', default => ''},
        Creator =>
		{read => 1, auto => 1, sql_type => 4, length => 11,  is_blob => 0,  is_numeric => 1,  type => 'int(11)', default => '0'},
        Created =>
		{read => 1, auto => 1, sql_type => 11, length => 0,  is_blob => 0,  is_numeric => 0,  type => 'datetime', default => ''},
   }
};

RT::Base->_ImportOverlays();

1;
