# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:concretecms:concrete_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903511");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"creation_date", value:"2014-02-19 16:18:17 +0530 (Wed, 19 Feb 2014)");
  script_cve_id("CVE-2014-5107", "CVE-2014-5108");
  script_name("Concrete5 < 5.6.3 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_portlandlabs_concrete_cms_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("concrete_cms/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20151026195213/http://www.concrete5.org/documentation/background/version_history/5-6-3-release-notes/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/31735");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/125280");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/127493");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122041141/http://www.securityfocus.com/bid/68685/");
  # nb: Link is 404 and no replacement has been found so far, kept here for historical reasons
  script_xref(name:"URL", value:"http://1337day.com/exploit/21919");

  script_tag(name:"summary", value:"Concrete5 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This script checks for the presence of the improper validation flaw which indicates that the
  system is also affected by the other included CVEs.");

  script_tag(name:"insight", value:"The following flaws exist:

  - No CVE: Improper validation of 'cID' parameter passed to the '/index.php' script

  - CVE-2014-5107: An information disclosure vulnerability

  - CVE-2014-5108: A cross-site scripting (XSS) vulnerability in single_pages\download_file.php");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to:

  - execute arbitrary SQL commands in applications database and gain complete control over the
  vulnerable web application

  - obtain the installation path via a direct request to various files

  - inject arbitrary web script or HTML via the HTTP Referer header to index.php/download_file");

  script_tag(name:"affected", value:"Concrete5 version 5.6.2.1 is known to be vulnerable. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 5.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/index.php/?arHandle=Main&bID=34&btask=passthru&ccm_token=" +
            "1392630914:be0d09755f653afb162d041a33f5feae&cID[$owmz]=1&" +
            "method=submit_form";

if( http_vuln_check( port:port, url:url, pattern:">mysqlt error:", extra_check:make_list( "Pages\.cID = Array", 'EXECUTE."select Pages\\.cID' ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
