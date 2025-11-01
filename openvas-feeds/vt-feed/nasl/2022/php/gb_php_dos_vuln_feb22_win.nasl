# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147658");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-02-18 02:27:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-07 23:00:00 +0000 (Mon, 07 Mar 2022)");

  script_cve_id("CVE-2021-21708");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.4.28, 8.0.x < 8.0.16, 8.1.x < 8.1.3 DoS Vulnerability (Feb 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When using filter functions with FILTER_VALIDATE_FLOAT filter
  and min/max limits, if the filter fails, there is a possibility to trigger use of allocated memory
  after free, which can result it crashes, and potentially in overwrite of other memory chunks and
  RCE.");

  script_tag(name:"affected", value:"PHP prior to version 7.4.28, 8.0.x through 8.0.15 and 8.1.x
  through 8.1.2.");

  script_tag(name:"solution", value:"Update to version 7.4.28, 8.0.16, 8.1.3 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.28");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.16");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.3");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=81708");

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

if (version_is_less(version: version, test_version: "7.4.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
