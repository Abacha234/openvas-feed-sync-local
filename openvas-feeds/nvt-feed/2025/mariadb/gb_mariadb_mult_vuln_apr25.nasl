# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125393");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-27 15:24:50 +0000 (Mon, 27 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-27 16:03:10 +0000 (Fri, 27 Jun 2025)");

  script_cve_id("CVE-2025-30693", "CVE-2025-30722");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("mariadb/detected");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-30693: This vulnerability allows high privileged attacker with network access via
  multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result
  in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
  Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible
  data.

  - CVE-2025-30722: This vulnerability allows low privileged attacker with network access via
  multiple protocols to compromise MySQL Client. Successful attacks of this vulnerability can result
  in unauthorized access to critical data or complete access to all MySQL Client accessible data as
  well as unauthorized update, insert or delete access to some of MySQL Client accessible data.");

  script_tag(name:"affected", value:"MariaDB versions prior to 10.5.29, 10.6.x prior to 10.6.22,
  10.7.x prior to 10.11.12, 11.0.x prior to 11.4.6.");

  script_tag(name:"solution", value:"Update to version 10.5.29, 10.6.22, 10.11.12, 11.4.6 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_xref(name:"URL", value:"https://mariadb.com/docs/server/security/securing-mariadb/security#full-list-of-cves-fixed-in-mariadb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.5.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.11.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.11.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
