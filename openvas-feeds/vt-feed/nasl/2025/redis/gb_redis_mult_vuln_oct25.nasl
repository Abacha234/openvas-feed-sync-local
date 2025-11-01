# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155542");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-06 02:41:52 +0000 (Mon, 06 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-07 15:40:02 +0000 (Tue, 07 Oct 2025)");

  script_cve_id("CVE-2025-46817", "CVE-2025-46818", "CVE-2025-46819", "CVE-2025-49844");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis Multiple Vulnerabilities (Oct 2025, RediShell)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_tcp_detect.nasl");
  script_mandatory_keys("redis/detected");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-46817: Lua library commands may lead to integer overflow and potential remote code
  execution (RCE)

  - CVE-2025-46818: Running Lua function as a different user

  - CVE-2025-46819: Out of bound read due to a bug in LUA

  - CVE-2025-49844: Lua Use-After-Free may lead to RCE and dubbed 'RediShell'");

  script_tag(name:"affected", value:"Redis prior to version 6.2.20, 7.2.x prior to 7.2.11,
  7.4.x prior to 7.4.6, 8.0.x prior to 8.0.4 and 8.2.x prior to 8.2.2.");

  script_tag(name:"solution", value:"Update to version 6.2.20, 7.2.11, 7.4.6, 8.0.4, 8.2.2 or
  later.");

  script_xref(name:"URL", value:"https://redis.io/blog/security-advisory-cve-2025-49844/");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-m8fj-85cg-7vhp");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-qrv7-wcrx-q5jp");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-4c68-q8q8-3g4f");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-4789-qfc9-5f9q");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.20");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.2.11");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.4.6");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/8.0.4");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/8.2.2");
  script_xref(name:"URL", value:"https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/07/2");
  script_xref(name:"URL", value:"https://redrays.io/blog/poc-for-cve-2025-49844-cve-2025-46817-and-cve-2025-46818-critical-lua-engine-vulnerabilities/");
  script_xref(name:"URL", value:"https://github.com/raminfp/redis_exploit");
  script_xref(name:"URL", value:"https://github.com/dwisiswant0/CVE-2025-46818");
  script_xref(name:"URL", value:"https://github.com/dwisiswant0/CVE-2025-46819");
  script_xref(name:"URL", value:"https://github.com/dwisiswant0/CVE-2025-49844");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.20");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.4.0", test_version_up: "7.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2.0", test_version_up: "8.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
