# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:e1200_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128181");
  script_version("2025-12-10T05:45:47+0000");
  script_tag(name:"last_modification", value:"2025-12-10 05:45:47 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-08 13:10:13 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-60689", "CVE-2025-60690", "CVE-2025-60691", "CVE-2025-60692",
                "CVE-2025-60694", "CVE-2025-60693");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Linksys E1200 Router Firmware version 2.0.11.001 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys E1200 routers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-60689: An unauthenticated command injection vulnerability exists in the Start_EPI
  function of the httpd binary on Linksys E1200 v2 routers (Firmware E1200_v2.0.11.001_us.tar.gz).
  Successful exploitation allows remote attackers to execute arbitrary commands on the device
  without authentication.

  - CVE-2025-60690: A stack-based buffer overflow exists in the get_merge_ipaddr function of the
  httpd binary on Linksys E1200 v2 routers (Firmware E1200_v2.0.11.001_us.tar.gz). Remote attackers
  can exploit this vulnerability via specially crafted HTTP requests to execute arbitrary code or
  cause denial of service without authentication.

  - CVE-2025-60691: A stack-based buffer overflow exists in the httpd binary of Linksys E1200 v2
  routers (Firmware E1200_v2.0.11.001_us.tar.gz). Remote attackers can exploit this vulnerability
  via crafted HTTP requests to execute arbitrary code or cause denial of service without
  authentication.

  - CVE-2025-60692: A stack-based buffer overflow vulnerability exists in the libshared.so library
  of Cisco Linksys E1200 v2 routers (Firmware E1200_v2.0.11.001_us.tar.gz). This allows local
  attackers controlling the contents of /proc/net/arp to overflow stack buffers, leading to memory
  corruption, denial of service, or potential arbitrary code execution.

  - CVE-2025-60694: A stack-based buffer overflow exists in the validate_static_route function of
  the httpd binary on Linksys E1200 v2 routers (Firmware E1200_v2.0.11.001_us.tar.gz). Remote
  attackers can exploit this vulnerability via specially crafted HTTP requests to execute
  arbitrary code or cause denial of service without authentication.

  - CVE-2025-60693: A stack-based buffer overflow exists in the get_merge_mac function of the httpd
  binary on Linksys E1200 v2 routers (Firmware E1200_v2.0.11.001_us.tar.gz). Remote attackers can
  exploit this vulnerability via specially crafted HTTP requests to execute arbitrary code or cause
  denial of service without authentication.");

  script_tag(name:"affected", value:"Linksys E1200 v2 routers with firmware versions 2.0.11.001.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The product has reached its end-of-life.");

  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E1200/CVE-2025-60689.md");
  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E1200/CVE-2025-60690.md");
  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E1200/CVE-2025-60691.md");
  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E1200/CVE-2025-60692.md");
  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E1200/CVE-2025-60694.md");
  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E1200/CVE-2025-60693.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"2.0.11.001" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
