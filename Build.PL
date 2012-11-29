
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "FindBin" => 0,
    "Module::Build" => "0.3601",
    "Test::Mojo" => 0,
    "Test::More" => 0
  },
  "configure_requires" => {
    "ExtUtils::MakeMaker" => "6.30",
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "LDAP back end for PlugAuth",
  "dist_author" => [
    "Graham Ollis <gollis\@sesda2.com>"
  ],
  "dist_name" => "PlugAuth-Plugin-LDAP",
  "dist_version" => "0.01",
  "license" => "restrictive",
  "module_name" => "PlugAuth::Plugin::LDAP",
  "recommends" => {},
  "recursive_test_files" => 1,
  "requires" => {
    "Log::Log4perl" => 0,
    "Net::LDAP" => 0,
    "PlugAuth" => 0,
    "PlugAuth::Role::Auth" => 0,
    "PlugAuth::Role::Plugin" => 0,
    "Role::Tiny::With" => 0,
    "perl" => "v5.10.0"
  },
  "script_files" => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
