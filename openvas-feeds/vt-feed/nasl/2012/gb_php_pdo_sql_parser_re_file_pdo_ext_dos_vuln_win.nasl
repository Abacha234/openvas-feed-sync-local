# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802670");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-08-27 17:03:25 +0530 (Mon, 27 Aug 2012)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2012-3450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.14, 5.4.x < 5.4.4 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the PDO extension in
  pdo_sql_parser.re file, which fails to determine the end of the query string during parsing of
  prepared statements.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service condition.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.14 and 5.4.x prior to 5.4.4 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 5.3.14, 5.4.4 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jun/60");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54777");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61755");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=769785");

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

if (version_is_less(version: version, test_version: "5.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
