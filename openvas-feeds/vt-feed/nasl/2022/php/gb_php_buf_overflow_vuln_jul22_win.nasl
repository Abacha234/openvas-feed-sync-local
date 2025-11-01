# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148417");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-07-08 03:16:35 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 23:19:00 +0000 (Wed, 03 Aug 2022)");

  script_cve_id("CVE-2022-31627");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 8.1.x < 8.1.8 Heap Buffer Overflow Vulnerability (Jul 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability occurs in fileinfo functions, such as
  finfo_buffer, due to incorrect patch applied to the third party code from libmagic, incorrect
  function may be used to free allocated memory, which may lead to heap corruption.");

  script_tag(name:"affected", value:"PHP version 8.1.x through 8.1.7.");

  script_tag(name:"solution", value:"Update to version 8.1.8 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.8");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=81723");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
