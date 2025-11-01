# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148021");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2022-05-03 02:18:49 +0000 (Tue, 03 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-09 17:15:00 +0000 (Mon, 09 May 2022)");

  script_cve_id("CVE-2022-24735", "CVE-2022-24736");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 6.2.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_tcp_detect.nasl");
  script_mandatory_keys("redis/detected");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-24735: Lua scripts can be manipulated to overcome ACL rules

  - CVE-2022-24736: A malformed Lua script can crash Redis");

  script_tag(name:"affected", value:"Redis prior to version 6.2.7.");

  script_tag(name:"solution", value:"Update to version 6.2.7 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-647m-2wmq-qmvq");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-3qpw-7686-5984");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
