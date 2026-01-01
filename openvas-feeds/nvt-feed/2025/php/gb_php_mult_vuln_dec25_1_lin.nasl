# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156071");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-19 05:18:31 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:C");

  script_cve_id("CVE-2025-14177", "CVE-2025-14178", "CVE-2025-14180");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.2.30, 8.3.x < 8.3.29, 8.4.x < 8.4.16 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-14177: Information leak of memory in getimagesize

  - CVE-2025-14178: Heap buffer overflow in array_merge()

  - CVE-2025-14180: PDO quoting result null deref

  - No CVE: Null byte termination in dns_get_record()");

  script_tag(name:"affected", value:"PHP versions prior to 8.2.30, 8.3.x prior to 8.3.29 and 8.4.x
  prior to 8.4.16.");

  script_tag(name:"solution", value:"Update to version 8.2.30, 8.3.29, 8.4.16 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.30");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.29");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.4.16");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3237-qqm7-mfv7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-h96m-rvf9-jgm2");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-8xr5-qppj-gvwj");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-www2-q4fc-65wf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.2.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
