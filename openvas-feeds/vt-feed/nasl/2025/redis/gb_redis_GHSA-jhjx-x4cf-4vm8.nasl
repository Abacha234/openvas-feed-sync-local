# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155701");
  script_version("2025-11-06T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-11-06 05:40:15 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-05 02:55:56 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-62507");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis Buffer Overflow Vulnerability (GHSA-jhjx-x4cf-4vm8)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_tcp_detect.nasl");
  script_mandatory_keys("redis/detected");

  script_tag(name:"summary", value:"Redis is prone to a stack-based buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user can run the XACKDEL command with multiple ID's and
  trigger a stack buffer overflow, which may potentially lead to remote code execution.");

  script_tag(name:"affected", value:"Redis version 8.2.x prior to 8.2.3.");

  script_tag(name:"solution", value:"Update to version 8.2.3 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-jhjx-x4cf-4vm8");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/8.2.3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.2.0", test_version_up: "8.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
