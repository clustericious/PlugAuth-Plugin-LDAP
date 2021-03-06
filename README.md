# PlugAuth::Plugin::LDAP [![Build Status](https://secure.travis-ci.org/clustericious/PlugAuth-Plugin-LDAP.png)](http://travis-ci.org/clustericious/PlugAuth-Plugin-LDAP)

(Deprecated) LDAP back end for PlugAuth

# SYNOPSIS

In your PlugAuth.conf file:

    ---
    ldap :
      server : ldap://198.118.255.141:389
      dn : uid=%s, ou=people, dc=users, dc=example, dc=com
      authoritative : 1

Note that %s in the dn will be replaced with the username
when binding to the LDAP server.

# DESCRIPTION

**NOTE**: This module has been deprecated, and may be removed on or after 31 December 2018.
Please see [https://github.com/clustericious/Clustericious/issues/46](https://github.com/clustericious/Clustericious/issues/46).

Handle authentication only from LDAP server.
Everything else is handled by [PlugAuth::Plugin::FlatAuth](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuth)
(e.g. authorization, groups, etc).

# METHODS

## PlugAuth::Plugin::LDAP->check\_credentials( $user, $password )

Given a user and password, check to see if the password is correct.

# SEE ALSO

[PlugAuth](https://metacpan.org/pod/PlugAuth), [PlugAuth::Routes](https://metacpan.org/pod/PlugAuth::Routes), [PlugAuth::Plugin::FlatAuth](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuth)

# AUTHOR

Graham Ollis <gollis@sesda3.com>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by NASA GSFC.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
