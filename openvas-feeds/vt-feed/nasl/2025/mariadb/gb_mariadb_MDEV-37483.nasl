# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119238");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-28 10:07:51 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-13699");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Directory Traversal RCE Vulnerability (Nov 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("mariadb/detected");

  script_tag(name:"summary", value:"MariaDB is prone to a directory traversal remote code execution
  (RCE) vulnerability in the mariadb-dump Utility.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific flaw exists within the handling of view names. The
  issue results from the lack of proper validation of a user-supplied path prior to using it in file
  operations. An attacker can leverage this vulnerability to execute code in the context of the
  current user.");

  script_tag(name:"impact", value:"This vulnerability allows remote attackers to execute arbitrary
  code on affected installations of MariaDB. Interaction with the mariadb-dump utility is required
  to exploit this vulnerability but attack vectors may vary depending on the implementation.");

  script_tag(name:"affected", value:"MariaDB versions prior to 10.6.24, 10.7.x prior to 10.11.15,
  11.x prior to 11.4.9 and 11.5.x prior to 11.8.4.");

  script_tag(name:"solution", value:"Update to version 10.6.24, 10.11.15, 11.4.9, 11.8.4 or
  later.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-1025/");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-37483");

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

if (version_is_less(version: version, test_version: "10.6.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.11.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.11.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.7.0", test_version_up: "11.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.5.0", test_version_up: "11.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
