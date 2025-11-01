# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103592");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-10-25 10:12:52 +0200 (Thu, 25 Oct 2012)");

  script_name("PHP Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of PHP.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

paths = ssh_find_file( file_name:"/php(-cli|[578](\.[0-9])?)?$", sock:sock, useregex:TRUE );
if( ! paths ) {
  ssh_close_connection();
  exit( 0 );
}

foreach path( paths ) {

  path = chomp( path );
  if( ! path )
    continue;

  # nb: Just a symlink on Debian systems to e.g. /usr/bin/php5 or /usr/bin/php7.0
  if( path == "/etc/alternatives/php" )
    continue;

  # PHP 5.6.30-0+deb8u1 (cli) (built: Feb  8 2017 08:50:21)
  # PHP 7.0.19-1 (cli) (built: May 11 2017 14:04:47) ( NTS )
  # PHP 7.4.3 (cli) (built: Jul  5 2021 15:13:35) ( NTS )
  vers = ssh_get_bin_version( full_prog_name:path, sock:sock, version_argv:"-vn", ver_pattern:"PHP ([^ ]+)" );
  if( ! vers[1] || vers[1] !~ "^[0-9.]{3,}" || "The PHP Group" >< vers[0] )
    continue;

  concluded = '    Command:\n      ' + path + " -vn";
  concluded += '\n    Result:\n      ' + vers[0];

  version = vers[1];

  set_kb_item( name:"php/detected", value:TRUE );
  set_kb_item( name:"php/ssh-login/detected", value:TRUE );
  set_kb_item( name:"php/ssh-login/port", value:port );
  set_kb_item( name:"php/ssh-login/" + port + "/installs", value:"0#---#" + path + "#---#" + version + "#---#" + concluded );
}

exit( 0 );