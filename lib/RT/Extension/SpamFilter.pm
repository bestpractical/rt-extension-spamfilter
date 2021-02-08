use strict;
use warnings;

package RT::Extension::SpamFilter;

our $VERSION = '0.03';

sub MessageScore {
    my $class = shift;
    my $message = shift;
    my @filters = RT->Config->Get('SpamFilters');
    my $score = 0;
    return $score unless @filters;
    my $head = $message->head;
    my $body;
    my ($part) = grep { !$_->is_multipart } $message->parts_DFS;
    if ( my $bh = $part->bodyhandle ) {
        $body = $bh->as_string;
    }
    else {
        $body = '';
    }

    my $content = $message->as_string;
    for my $filter ( @filters ) {
        next unless $filter && $filter->{Field} && $filter->{Regex} && $filter->{Score};
        if ( $filter->{Field} eq 'Body' ) {
            $score += $filter->{Score} if $body =~ $filter->{Regex};
        }
        else {
            $score += $filter->{Score} if $head->get($filter->{Field}) =~ $filter->{Regex};
        }
    }
    return $score;
}

=head1 NAME

RT-Extension-SpamFilter - Spam Filter

=head1 DESCRIPTION

This is for public RT systems, where everyone can create tickets.  Admins can define a list of rules, and if an email
comes from a non-existing user and reached the score threshold(scored by the rules), it will be marked as spam and no
tickets will be created.

Admins can manually handle those spams from /Tools/SpamFilter/List.html

=head1 RT VERSION

Works with RT 4.0, 4.2, 4.4 and 5.0.

=head1 INSTALLATION

=over

=item C<perl Makefile.PL>

=item C<make>

=item C<make install>

May need root permissions

=item C<make initdb>

Only run this the first time you install this module.

If you run this twice, you may end up with duplicate data
in your database.

If you are upgrading this module, check for upgrading instructions
in case changes need to be made to your database.

=item Patch RT earlier than 5.0.2

    patch -d /opt/rt5 -p1 < patches/0001-Pass-action-info-to-GetCurrentUser-for-email-interfa.patch

=item Set up spam filter rules (see L</"CONFIGURATION"> for details.)

=item Clear your mason cache

    rm -rf /opt/rt5/var/mason_data/obj

=item Restart your webserver

=back

=head1 CONFIGURATION

Edit your F</opt/rt5/etc/RT_SiteConfig.pm>; a sample configuration
is shown below:

    Plugin('RT::Extension::SpamFilter');
    Set(@MailPlugins, 'SpamFilter', 'Auth::MailFrom');
    Set($SpamFilterThreshold, 30);
    Set(
        @SpamFilters,
        {
            Field => 'Subject',
            Regex => qr/urgent reply/i,
            Score => 20,
        },
        {
            Field => 'X-Gm-Spam',
            Regex => qr/1/,
            Score => 30, # Trust spam header and flag as spam
        },
        {
            Field => 'Body',
            Regex => qr/download the attachment/i,
            Score => 10
        }
    );

=head2 C<@SpamFilters>

The C<@SpamFilters> array is an array of hashes.  Each hash
must contain the following keys:

=over

=item C<Field>

Either 'Body' or the name of an email header.

=item C<Regex>

A regular expression to apply to the email header named
by C<Field> (or the email body if C<Field> is 'Body').

=item C<Score>

A number indicating how many points to add to the
spam score if the rule matches.

=back

You can use the configuration above to check for provided spam headers
as shown in the example above. However, any score provided as a value in a
header currently isn't used. The configuration will detect the
presence of the spam header and then add the score you configure.

=head2 C<$SpamFilterThreshold>

The C<$SpamFilterThreshold> is the score above which an incoming message
is considered to be spam and placed in the spam list.

=head1 AUTHOR

Best Practical Solutions, LLC E<lt>modules@bestpractical.comE<gt>

=head1 BUGS

All bugs should be reported via email to

    L<bug-RT-Extension-SpamFilter@rt.cpan.org|mailto:bug-RT-Extension-SpamFilter@rt.cpan.org>

or via the web at

    L<rt.cpan.org|http://rt.cpan.org/Public/Dist/Display.html?Name=RT-Extension-SpamFilter>.

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2014 Best Practical Solutions, LLC.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991

=cut

1;
