use strict;
use warnings;
use 5.010;
use Test::Clustericious::Log;
use Test::Clustericious::Cluster;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 15;
use Test::Mojo;

my $t = Test::Mojo->new('PlugAuth');

use YAML ();
note YAML::Dump($t->app->config);

our $net_ldap_saw_user;
our $net_ldap_saw_password;

my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

# good user, good password
$t->get_ok("http://optimus:matrix\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

is $net_ldap_saw_user, 'optimus', 'user = optimus';
is $net_ldap_saw_password, 'matrix', 'password = matrix';

# good user, bad password
$t->get_ok("http://optimus:badguess\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth succeeded');

is $net_ldap_saw_user, 'optimus', 'user = optimus';
is $net_ldap_saw_password, 'badguess', 'password = badguess';

# good user, bad password
$t->get_ok("http://bogus:matrix\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth succeeded');

is $net_ldap_saw_user, 'bogus', 'user = bogus';
is $net_ldap_saw_password, 'matrix', 'password = matrix';

__DATA__

@@ lib/Net/LDAP.pm
package Net::LDAP;

use strict;
use warnings;
use Net::LDAP::Message;

sub new
{
  bless {}, 'Net::LDAP';
}

sub bind
{
  my($self, $dn, %args) = @_;

  if($dn =~ /^uid=([a-z]+), ou=people, dc=users, dc=example, dc=com$/)
  { $main::net_ldap_saw_user = $1 }
  else
  { $main::net_ldap_saw_user = '---' }
  $main::net_ldap_saw_password = $args{password};

  my $code = !($main::net_ldap_saw_user eq 'optimus' && $main::net_ldap_saw_password eq 'matrix');
  bless { code => $code }, 'Net::LDAP::Message';
}

package Net::LDAP::Message;

sub code { shift->{code} }
sub error { shift->{code} ? 'unauthorized' : 'authorized' }

1;
