# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803341");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-03-21 16:27:46 +0530 (Thu, 21 Mar 2013)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2012-1172");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities - 01 (Mar 2013) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw due to insufficient validation of file-upload
  implementation in rfc1867.c and it does not handle invalid '[' characters in name values.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to retrieve,
  corrupt or upload arbitrary files, or can cause denial of service via corrupted $_FILES
  indexes.");

  script_tag(name:"affected", value:"PHP version before 5.4.0");

  script_tag(name:"solution", value:"Update to PHP 5.4.0 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53403");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2012-1172");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-1172");

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

if (version_is_less(version: version, test_version: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
