# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801584");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-4700");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.2 <= 5.3.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'set_magic_quotes_runtime()'
  when the MySQLi extension is used, which fails to properly interact with use of the
  'mysqli_fetch_assoc()' function.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to conduct
  SQL injection attacks via crafted input that had been properly handled in earlier versions.");

  script_tag(name:"affected", value:"PHP version 5.3.2 to 5.3.3.");

  script_tag(name:"solution", value:"Update to version 5.3.5 or later.");

  script_xref(name:"URL", value:"http://bugs.php.net/52221");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

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

if (version_in_range(version: version, test_version: "5.3.2", test_version2: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
