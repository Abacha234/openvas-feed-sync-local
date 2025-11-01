# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803164");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-01-24 16:39:00 +0530 (Thu, 24 Jan 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-6113");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 'openssl_encrypt()' Function Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'openssl_encrypt()' function when
  handling empty $data strings which will allow an attacker to gain access to arbitrary pieces of
  information in current memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information from process memory by providing zero bytes of input data.");

  script_tag(name:"affected", value:"PHP version 5.3.9 through 5.3.13 on Windows");

  script_tag(name:"solution", value:"Apply the patch or upgrade to the latest version from the
  references.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57462");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81400");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commitdiff;h=270a406ac94b5fc5cc9ef59fc61e3b4b95648a3e");

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

if (version_in_range(version: version, test_version: "5.3.9", test_version2: "5.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
