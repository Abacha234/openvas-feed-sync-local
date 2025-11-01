# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112136");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-11-23 10:47:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OPENVAS SCAN / Greenbone Enterprise Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS) (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("greenbone/gos", "greenbone/gos/uname");

  script_tag(name:"summary", value:"SSH login-based detection of OPENVAS SCAN / Greenbone Enterprise
  Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! get_kb_item( "greenbone/gos" ) )
  exit( 0 );

if( ! uname = get_kb_item( "greenbone/gos/uname" ) )
  exit( 0 );

port = kb_ssh_transport();

version = "unknown";
type = "unknown";

set_kb_item( name:"greenbone/gos/detected", value:TRUE );
set_kb_item( name:"greenbone/gos/ssh-login/detected", value:TRUE );
set_kb_item( name:"greenbone/gos/ssh-login/port", value:port );

vers = eregmatch( pattern:'Welcome to the Greenbone OS ([^ ]+) ', string:uname );
if( ! isnull( vers[1] ) && vers[1] =~ "^([0-9.-]+)$" ) {
  version = vers[1];
  concluded = '\n    ' + vers[0];
} else {

  # GOS 4.x+ doesn't report the version in its login banner
  banner = egrep( pattern:"^Welcome to the Greenbone OS.*", string:uname );
  if( banner ) {
    sock = ssh_login_or_reuse_connection();

    # Available since GOS 4+
    cmd = "gsmctl info gsm-info.full_version";
    gsm_info = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:FALSE );
    if( gsm_info && gsm_info =~ "^([0-9.]+)$" ) {

      version = gsm_info;

      concluded += '\n    Command:  ' + cmd;
      concluded += '\n    Response: ' + gsm_info;
    }
  }
}

_type = eregmatch( pattern:'running on a Greenbone Security Manager ([^ \r\n]+)', string:uname );
if( _type[1] ) {
  type = _type[1];
  concluded += '\n    ' + _type[0];
} else {

  # Available since GOS 4+
  sock = ssh_login_or_reuse_connection();
  cmd = "gsmctl info gsm-info.type";
  gsm_info = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:FALSE );
  if( gsm_info && gsm_info =~ "^([a-zA-Z0-9.]+)$" ) {

    # nb: This has e.g. "one" in lower case
    type = toupper( gsm_info );

    concluded += '\n    Command:  ' + cmd;
    concluded += '\n    Response: ' + gsm_info;
  }
}

set_kb_item( name:"greenbone/gsm/ssh-login/" + port + "/type", value:type );
set_kb_item( name:"greenbone/gos/ssh-login/" + port + "/version", value:version );

# nb: Shouldn't happen but still adding it just to be sure...
if( ! concluded )
  concluded = '\n    ' + uname;

set_kb_item( name:"greenbone/gos/ssh-login/" + port + "/concluded", value:concluded );

exit( 0 );
