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

package RT::Interface::Email::SpamFilter;

use strict;
use warnings;

use Role::Basic 'with';
with 'RT::Interface::Email::Role';

use RT::Interface::Email;
use RT::Spam;

=head1 NAME

RT::Interface::Email::SpamFilter

=head1 SYNOPSIS

=cut

sub GetCurrentUser {
    my %args = (
        Message => undef,
        @_,
    );

    my ( $Address, $Name, @errors ) = RT::Interface::Email::ParseSenderAddressFromHead( $args{'Message'}->head );
    $RT::Logger->warning("Failed to parse ".join(', ', @errors))
        if @errors;

    unless ( $Address ) {
        $RT::Logger->error("Couldn't parse or find sender's address");
        FAILURE("Couldn't parse or find sender's address");
    }

    my $CurrentUser = RT::CurrentUser->new;
    $CurrentUser->LoadByEmail( $Address );
    $CurrentUser->LoadByName( $Address ) unless $CurrentUser->Id;
    if ( $CurrentUser->Id ) {
        $RT::Logger->debug("Mail from user #". $CurrentUser->Id ." ($Address)" );
        return $CurrentUser;
    }

    my ( $score ) = RT::Extension::SpamFilter->MessageScore($args{'Message'});
    if ( $score >= RT->Config->Get( 'SpamFilterThreshold' ) || 0 ) {
        my $email = RT::Spam->new( RT->SystemUser );
        my ( $ret, $message ) =
          $email->Create( Message => $args{Message}, RawMessage => ${ $args{RawMessage} }, Status => 'new', Score => $score );
        if ( !$ret ) {
            RT->Logger->error( "Failed to create Spam record: $message" );
        }
    }

    SUCCESS();
}

1;
