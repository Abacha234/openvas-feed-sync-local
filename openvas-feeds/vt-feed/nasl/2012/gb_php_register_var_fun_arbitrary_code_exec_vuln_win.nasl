# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802590");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-02-10 11:24:19 +0530 (Fri, 10 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-0830");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.9 RCE Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a remote arbitrary code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a logic error within the
  'php_register_variable_ex()' function in php_variables.c when hashing form posts and updating a
  hash table, which can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary PHP code on the system.");

  script_tag(name:"affected", value:"PHP version 5.3.9 on windows.");

  script_tag(name:"solution", value:"Update to version 5.3.10 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51830");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72911");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.3.10");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=15408");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/cve/CVE-2012-0830");

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

if (version_is_equal(version: version, test_version: "5.3.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
