# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105623");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"creation_date", value:"2016-04-26 13:10:26 +0200 (Tue, 26 Apr 2016)");
  script_name("Cisco Finesse Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco Finesse.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/finesse/detected");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! get_kb_item( "cisco/finesse/detected" ) )
  exit( 0 );

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

show_ver = ssh_cmd( socket:sock, cmd:"show version active", nosh:TRUE, pty:TRUE, timeout:60, retry:30, pattern:"Active Master Version:" );
if( ! show_ver || "Active Master Version:" >!< show_ver )
  exit( 0 );

cpe = "cpe:/a:cisco:finesse";
vers = "unknown";
install = "/";

# Example: 10.5.1.10000-3
version = eregmatch( pattern:'Active Master Version: ([^\r\n]+)', string:show_ver );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  set_kb_item( name:"cisco/finesse/version", value:vers );
  cpe += ":" + vers;
}

register_product( cpe:cpe, port:0, location:install, service:"ssh-login" );

log_message( data:build_detection_report( app:"Cisco Finesse",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:"show version active" ),
             port:0 );

exit( 0 );
