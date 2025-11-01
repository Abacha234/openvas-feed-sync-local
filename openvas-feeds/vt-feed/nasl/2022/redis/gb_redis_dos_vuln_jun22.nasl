# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126056");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2022-07-01 08:50:30 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-29 18:08:00 +0000 (Wed, 29 Jun 2022)");

  script_cve_id("CVE-2022-33105");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 7.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_tcp_detect.nasl");
  script_mandatory_keys("redis/detected");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing a streamIteratorStop() function in a streamGetEdgeID
  component may lead to a memory leak in XADD and XTRIM.");

  script_tag(name:"affected", value:"Redis version 7.0.");

  script_tag(name:"solution", value:"Update to version 7.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/pull/10753");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-35rf-7vhx-9phr");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/redis/redis/7.0.1/00-RELEASENOTES");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
