# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145115");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-01-11 08:24:25 +0000 (Mon, 11 Jan 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-15 15:15:00 +0000 (Thu, 15 Jul 2021)");

  script_cve_id("CVE-2020-7071");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.3.26, 7.4.x < 7.4.14, 8.0.x < 8.0.1 Filter Vulnerability (Jan 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a vulnerability where FILTER_VALIDATE_URL
  accepts URLs with invalid userinfo.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP versions prior to 7.3.26, 7.4.x prior to 7.4.14 and 8.0.x
  prior to 8.0.1.");

  script_tag(name:"solution", value:"Update to version 7.3.26, 7.4.14, 8.0.1 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.26");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.14");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.1");

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

if (version_is_less(version: version, test_version: "7.3.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.4.0", test_version2: "7.4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
