# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104332");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-09-29 10:44:11 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:32:00 +0000 (Fri, 30 Sep 2022)");

  script_cve_id("CVE-2022-31628", "CVE-2022-31629");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.4.31, 8.0.x < 8.0.24, 8.1.x < 8.1.11 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-31628: The phar uncompressor code would recursively uncompress 'quines' gzip files,
  resulting in an infinite loop.

  - CVE-2022-31629: The vulnerability enables network and same-site attackers to set a standard
  insecure cookie in the victim's browser which is treated as a '__Host-' or '__Secure-' cookie by
  PHP applications.");

  script_tag(name:"affected", value:"PHP versions prior to 7.4.31, 8.0.x prior to 8.0.24 and 8.1.x
  prior to 8.1.11.");

  script_tag(name:"solution", value:"Update to version 7.4.31, 8.0.24, 8.1.11 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.31");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.24");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.11");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=81726");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=81727");

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

if (version_is_less(version: version, test_version: "7.4.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
