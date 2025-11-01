# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803677");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-06-25 17:10:23 +0530 (Tue, 25 Jun 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2013-4636");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.4.x < 5.4.16 DoS Vulnerability (Jun 2013) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw in 'mget' function in libmagic/softmagic.c, which
  triggers incorrect MIME type detection during access to an finfo object.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial
  of service (invalid pointer dereference and application crash) via an MP3 file.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.x prior to 5.4.16.");

  script_tag(name:"solution", value:"Update to version 5.4.16 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60728");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=64830");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-4636");

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

if (version_in_range(version: version, test_version: "5.4", test_version2: "5.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
