# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803337");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-03-14 18:10:04 +0530 (Thu, 14 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-1635", "CVE-2013-1643");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.23, 5.4.x < 5.4.13 Multiple Vulnerabilities (Mar 2013) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Does not validate 'soap.wsdl_cache_dir' directive before writing SOAP wsdl cache files to the
  filesystem.

  - Allows the use of external entities while parsing SOAP wsdl files, issue in 'soap_xmlParseFile'
  and 'soap_xmlParseMemory' functions.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to read arbitrary
  files and write wsdl files within the context of the affected application.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.23 and 5.4.x prior to 5.4.13.");

  script_tag(name:"solution", value:"Update to version 5.3.23, 5.4.13 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58224");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=64360");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-1635");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-1643");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=459904");

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

if (version_is_less(version: version, test_version: "5.3.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
