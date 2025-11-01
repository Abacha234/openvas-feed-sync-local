# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801585");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2006-7243", "CVE-2010-4699", "CVE-2011-0753", "CVE-2011-0754",
                "CVE-2011-0755");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.4 Multiple Security Bypass Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An error in handling pathname which accepts the '?' character in a pathname.

  - An error in 'iconv_mime_decode_headers()' function in the 'Iconv' extension.

  - 'SplFileInfo::getType' function in the Standard PHP Library (SPL) extension, does not properly
  detect symbolic links in windows.

  - Integer overflow in the 'mt_rand' function.

  - Race condition in the 'PCNTL extension', when a user-defined signal handler exists.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to trigger
  an incomplete output array, and possibly bypass spam detection or have unspecified other
  impact.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.4.");

  script_tag(name:"solution", value:"Update to version 5.3.4 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_3_4.php");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2010/12/09/9");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=305507");

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

if (version_is_less(version: version, test_version: "5.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
