# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:re7000_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128183");
  script_version("2025-12-10T05:45:47+0000");
  script_tag(name:"last_modification", value:"2025-12-10 05:45:47 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-09 08:11:08 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-60696");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Linksys RE7000 Router Firmware version 2.0.15_211230_1012 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys RE7000 routers are prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow vulnerability exists in the
  makeRequest.cgi binary of Linksys RE7000 routers (Firmware FW_v2.0.15_211230_1012). The arplookup
  function parses lines from /proc/net/arp using sscanf('%16s ... %18s ...'), storing results into
  buffers v6 (12 bytes) and v7 (20 bytes). Since the format specifiers allow up to 16 and 18 bytes
  respectively, oversized input can overflow the buffers, resulting in stack corruption. Local
  attackers controlling /proc/net/arp contents can exploit this issue to cause denial of service
  or potentially execute arbitrary code.");

  script_tag(name:"affected", value:"Linksys RE7000 routers with firmware version
  2.0.15_211230_1012.");

  script_tag(name:"solution", value:"No known solution is available as of 09th December, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-RE700/CVE-2025-60696.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"2.0.15_211230_10012" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
