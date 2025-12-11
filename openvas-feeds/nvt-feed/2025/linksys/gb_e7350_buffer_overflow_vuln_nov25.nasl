# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:e7350_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128182");
  script_version("2025-12-10T05:45:47+0000");
  script_tag(name:"last_modification", value:"2025-12-10 05:45:47 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-08 15:11:08 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2025-60695");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Linksys E7350 Router Firmware version 1.1.00.032 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys E7350 routers are prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow vulnerability exists in the
  mtk_dut binary of Linksys E7350 routers (Firmware 1.1.00.032). The function sub_4045A8 reads up
  to 256 bytes from /sys/class/net/%s/address into a local buffer and then copies it into
  caller-provided buffer a1 using strcpy without boundary checks. Since a1 is often allocated with
  significantly smaller sizes (20-32 bytes), local attackers controlling the contents of
  /sys/class/net/%s/address can trigger buffer overflows, leading to memory corruption,
  denial of service, or potential arbitrary code execution.");

  script_tag(name:"affected", value:"Linksys E7350 routers with firmware version 1.1.00.032.");

  script_tag(name:"solution", value:"No known solution is available as of 08th December, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/yifan20020708/SGTaint-0-day/blob/main/Linksys/Linksys-E7350/CVE-2025-60695.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"1.1.00.032" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
