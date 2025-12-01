# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125510");
  script_version("2025-11-19T05:40:23+0000");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-18 09:10:41 +0000 (Tue, 18 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2025-62519");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 4.0.14 SQLi Vulnerability (GHSA-fxm2-cmwj-qvx4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated SQLi vulnerability in the main
  configuration update functionality allows a privileged user with 'Configuration Edit'
  permissions to execute arbitrary SQL commands.");

  script_tag(name:"impact", value:"Successful exploitation can lead to a full
  compromise of the database, including reading, modifying, or deleting all data, as well as
  potential remote code execution depending on the database configuration.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 4.0.14.");

  script_tag(name:"solution", value:"Update to version 4.0.14 or later.");

  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-fxm2-cmwj-qvx4");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/compare/4.0.13...4.0.14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.14",
                            install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
