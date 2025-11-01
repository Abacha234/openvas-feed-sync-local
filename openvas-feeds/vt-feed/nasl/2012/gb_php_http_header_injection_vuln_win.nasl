# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802966");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-09-24 18:58:41 +0530 (Mon, 24 Sep 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-1398", "CVE-2012-4388");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.11, 5.4.0 < 5.4.1 RC1 HTTP Header Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to an HTTP header injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The sapi_header_op function in main/SAPI.c in PHP does not
  properly determine a pointer during checks for %0D sequences.");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to insert
  arbitrary headers, conduct cross-site request-forgery, cross-site scripting, HTML-injection, and
  other attacks.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.11 and 5.4.x through 5.4.0RC2 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 5.4.1 or later.");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/09/02/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55527");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/09/07/3");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.comp.php.devel/70584");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/09/05/15");
  script_xref(name:"URL", value:"http://security-tracker.debian.org/tracker/CVE-2012-4388");

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

if (version_is_less(version: version, test_version: "5.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.0.rc2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
