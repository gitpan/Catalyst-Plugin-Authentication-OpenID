# $Id: OpenID.pm 1019 2005-11-12 06:39:59Z btrott $

package Catalyst::Plugin::Authentication::OpenID;
use strict;

use Net::OpenID::Consumer;
use LWPx::ParanoidAgent;

our $VERSION = '0.01';

sub authenticate_openid {
    my($c) = @_;
    
    my $csr = Net::OpenID::Consumer->new(
        ua => LWPx::ParanoidAgent->new,
        args => $c->req->params,
        consumer_secret => sub { $_[0] },
    );
    
    if (my $uri = $c->req->param('claimed_uri')) {
        my $identity = $csr->claimed_identity($uri)
            or Catalyst::Exception->throw($csr->err);
        my $check_url = $identity->check_url(
            return_to => $c->req->base . '?openid-check=1',
            trust_root => $c->req->base,
        );
        $c->res->redirect($check_url);
        return 0;
    } elsif ($c->req->param('openid-check')) {
        if (my $setup_url = $csr->user_setup_url) {
            $c->res->redirect($setup_url);
            return 0;
        } elsif ($csr->user_cancel) {
            return 0;
        } elsif (my $identity = $csr->verified_identity) {
            $c->req->{openid_identity} = $identity;
            return 1;
        } else {
            Catalyst::Exception->throw("Error validating identity: " .
                $csr->err);
        }
    } else {
        return 0;
    }
}

1;
__END__

=head1 NAME

Catalyst::Plugin::Authentication::OpenID - OpenID Authentication

=head1 SYNOPSIS

    use Catalyst qw( Authentication::OpenID );

    sub begin : Private {
        my($self, $c) = @_;
        if ($c->authenticate_openid) {
            my $identity = $c->req->{openid_identity};
        } else {
            $c->res->redirect('<your-login-screen>')
                unless $c->res->redirect;
        }
    }

=head1 DESCRIPTION

I<Catalyst::Plugin::Authentication::OpenID> implements support for OpenID
authentication in a Catalyst application. For more information on OpenID,
take a look at I<http://www.openid.net/>.

In most cases, you'll want to use this plugin in combination with a session
plugin for Catalyst. For example, I<Catalyst::Plugin::Session::FastMmap>,
which uses a memory-mapped database to store session data. For an example,
take a look below at L<EXAMPLE>.

=head1 USAGE

=head2 $c->authenticate_openid

Attempts to authenticate the request using OpenID.

There are three phases in OpenID authentication, which means that
I<authenticate_openid> will actually be invoked multiple times, on
different requests.

It will return C<1> if the user was successfully authenticated, and
C<0> otherwise. Since the OpenID authentication protocol involves a number
of redirects, I<authenticate_openid> will automatically install redirects
in I<$c-E<gt>response>.

After a successful authentication, your application can fetch the identity
of the authenticated user through I<$c-E<gt>req-E<gt>{openid_identity}>,
a I<Net::OpenID::VerifiedIdentity> object.

=over 4

=item 1.

When the initial request arrives for your application, the user will not yet
have entered any authentication credentials. In this state,
I<authenticate_openid> will return C<0>, and will not set a redirect URI.

Your application must present a login form that will allow the user to enter
his or her OpenID identity URI; the form action should point back at your
Catalyst application.

=item 2.

Given the identity URI, I<authenticate_openid> will look up the user's
identity server, and will automatically install a redirect in
I<$c-E<gt>response> that points to the appropriate check URI for the
identity server. It will return C<0> in this state, as well.

The user will then be redirected to the identity server, where he/she
will either be recognized, or be forced to log in.

=item 3.

Once the user has successfully authenticated on the remote server, the
identity server will redirect back to your application. I<authenticate_openid>
will again be invoked, this time with state telling it to verify the
response from the identity server.

If the authentication is successful, I<authenticate_openid> will return
C<1>, and set I<$c-E<gt>req-E<gt>{openid_identity}>.

=back

Confused? The L<EXAMPLE> may help to clear it up.

=head1 EXAMPLE

I<Catalyst::Plugin::Authentication::OpenID> is best used combined with a
Catalyst session plugin, like I<Catalyst::Plugin::Session::FastMmap>. In
general, all of the session plugins have a similar interface, so the
example below should work with that share this interface.

This example uses a I<begin> method in the main application class to force
authentication throughout the application. It first checks to see whether
the request included a session ID, and if so, it simply looks up a user
account based on the user ID in the session.

In the other case, however, where the request does not have a session,
it attempts to use I<authenticate_openid> to authenticate the request. If
the authentication is successful, we have a verified identity, so we can
either load an existing user record, or provision a new account.

If the authentication is not successful, the assumption is that either
I<authenticate_openid> has set a redirect for where we need to send the user,
or no authentication credentials were provided at all. In the latter case,
we can just send the user off to our application's login form.

B<Note:> the only bit of voodoo here is the C<$c-E<gt>req-E<gt>action(undef);>
code. This seems to be necessary to force Catalyst not to handle the rest
of the request, and to just issue the redirect right away.

    sub begin : Private {
        my($self, $c) = @_;
        my $session = $c->session;
        return if $c->req->action eq 'login';
        if ($c->sessionid && $c->session->{user_id}) {
            $c->req->{user} = My::User->lookup($c->session->{user_id});
        } else {
            if ($c->authenticate_openid) {
                $c->req->{user} = $c->get_user($c->req->{openid_identity});
                $c->session->{user_id} = $c->req->{user}->user_id;
                $c->req->action(undef);
                $c->res->redirect('/');
            } else {
                $c->req->action(undef);
                $c->res->redirect('/login')
                    unless $c->res->redirect;
            }
        }
    }

    sub get_user {
        my $c = shift;
        my($identity) = @_;
        ## Lookup or provision a user account, using the $identity.
    }

=head1 SEE ALSO

L<Net::OpenID::Consumer>, L<LWPx::ParanoidAgent>

=head1 AUTHOR

Six Apart, cpan@sixapart.com

=head1 LICENSE

I<Catalyst::Plugin::Authentication::OpenID> is free software; you may
redistribute it and/or modify it under the same terms as Perl itself.

=head1 AUTHOR & COPYRIGHT

Except where otherwise noted, I<Catalyst::Plugin::Authentication::OpenID>
is Copyright 2005 Six Apart, cpan@sixapart.com. All rights reserved.

=cut
