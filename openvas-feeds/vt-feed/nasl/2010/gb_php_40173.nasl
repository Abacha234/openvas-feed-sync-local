# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100643");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2094", "CVE-2010-2950");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.x <= 5.3.2 Multiple Format String Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple format-string vulnerabilities because
  it fails to properly sanitize user-supplied input before passing it as the format specifier to a
  formatted-printing function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to run arbitrary code within
  the context of the PHP process. This may allow them to bypass intended security restrictions or
  gain elevated privileges.");

  script_tag(name:"affected", value:"PHP 5.3 through 5.3.2 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for
  details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40173");
  script_xref(name:"URL", value:"http://www.mail-archive.com/php-cvs@lists.php.net/msg46330.html");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=298667");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-024-php-phar_stream_flush-format-string-vulnerability/index.html");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-025-php-phar_wrapper_open_dir-format-string-vulnerability/index.html");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-026-php-phar_wrapper_unlink-format-string-vulnerability/index.html");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-027-php-phar_parse_url-format-string-vulnerabilities/index.html");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-028-php-phar_wrapper_open_url-format-string-vulnerabilities/index.html");

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

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
