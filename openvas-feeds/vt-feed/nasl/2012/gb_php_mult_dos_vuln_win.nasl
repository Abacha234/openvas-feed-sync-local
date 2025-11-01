# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802566");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-01-23 11:30:34 +0530 (Mon, 23 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-4153", "CVE-2012-0781");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple DoS Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error in application which makes calls to the 'zend_strndup()' function without checking the
  returned values. A local user can run specially crafted PHP code to trigger a null pointer
  dereference in zend_strndup() and cause the target service to crash.

  - An error in 'tidy_diagnose' function, which might allows remote attackers to cause a denial of
  service via crafted input.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause
  denial of service conditions.");

  script_tag(name:"affected", value:"PHP version 5.3.8 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.4.0 or later.");

  script_xref(name:"URL", value:"http://cxsecurity.com/research/103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51417");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026524");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18370/");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-01/0092.html");

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

if (version_is_equal(version: version, test_version: "5.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
