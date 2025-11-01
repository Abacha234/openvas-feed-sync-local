# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802330");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-1657", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3267",
                "CVE-2011-3268");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities (Sep 2011) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2011-2483: Improper handling of passwords with 8-bit characters by 'crypt_blowfish'
  function.

  - CVE-2011-1657: Error in 'ZipArchive::addGlob' and 'ZipArchive::addPattern' functions in
  ext/zip/php_zip.c file allows remote attackers to cause denial of service via certain flags
  arguments.

  - CVE-2011-3182: Improper validation of the return values of the malloc, calloc and realloc
  library functions.

  - CVE-2011-3267: Improper implementation of the error_log function.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code, obtain sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.7 on Windows.");

  script_tag(name:"solution", value:"Update to PHP version 5.3.7 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44874/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49252");
  script_xref(name:"URL", value:"http://www.php.net/archive/2011.php#id2011-08-18-1");

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

if (version_is_less(version: version, test_version: "5.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
