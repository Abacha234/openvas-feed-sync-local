# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802591");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-02-10 11:24:19 +0530 (Fri, 10 Feb 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-0831");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.10 Security Bypass Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in importing environment
  variables, it not properly performing a temporary change to the 'magic_quotes_gpc' directive
  during the importing of environment variables.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain
  sensitive information via a crafted request.");

  script_tag(name:"affected", value:"PHP version 5.3.9 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 5.3.10 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51954");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=323016");

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

if (version_is_less(version: version, test_version: "5.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
