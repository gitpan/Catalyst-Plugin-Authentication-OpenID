# $Id$

use inc::Module::Install;

name('Catalyst-Plugin-Authentication-OpenID');
abstract('OpenID Authentication for Catalyst applications');
author('Six Apart <cpan@sixapart.com>');
version_from('lib/Catalyst/Plugin/Authentication/OpenID.pm');
license('perl');
no_index(directory => 't');
sign(0);

include('ExtUtils::AutoInstall');

requires('Catalyst');
requires('Net::OpenID::Consumer');
requires('LWPx::ParanoidAgent');

auto_include();
auto_install();

&WriteAll;
