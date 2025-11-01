# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802349");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-12-01 11:41:26 +0530 (Thu, 01 Dec 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2011-4566");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP EXIF Header DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in
  'exif_process_IFD_TAG' function in the 'ext/exif/exif.c' file, Allows remote attackers to cause
  denial of service via crafted offset_val value in an EXIF header.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code, obtain sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.0 beta 4 on Windows.");

  script_tag(name:"solution", value:"Update to PHP version 5.4.0 beta 4 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=60150");
  script_xref(name:"URL", value:"http://olex.openlogic.com/wazi/2011/php-5-4-0-medium/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-4566");

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

if (version_is_less(version: version, test_version: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.0 beta 4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
