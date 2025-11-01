# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803317");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-03-01 12:30:11 +0530 (Fri, 01 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2012-2688");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.15, 5.4.x < 5.4.5 Buffer Overflow Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw related to overflow in the _php_stream_scandir function
  in the stream implementation.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
  arbitrary code and failed attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.15 and 5.4.x prior to 5.4.5.");

  script_tag(name:"solution", value:"Update to version 5.3.15, 5.4.5 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54638");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/427456.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-2688");

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

if (version_is_less(version: version, test_version: "5.3.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
