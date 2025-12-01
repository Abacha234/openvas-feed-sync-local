# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sensiolabs:symfony";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.133116");
  script_version("2025-11-18T05:39:54+0000");
  script_tag(name:"last_modification", value:"2025-11-18 05:39:54 +0000 (Tue, 18 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-17 08:45:09 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2025-64500");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony Incorrect Authorization Vulnerability (GHSA-3rg7-wf37-54rm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to an incorrect authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The 'Request' class improperly interprets some PATH_INFO in a
  way that leads to representing some URLs with a path that doesn't start with a '/'. This can
  allow bypassing some access control rules that are built with this '/'-prefix assumption.");

  script_tag(name:"affected", value:"Symfony prior to version 5.4.50, 6.x prior to 6.4.29 and 7.x
  prior to 7.3.7.");

  script_tag(name:"solution", value:"Update to version 5.4.50, 6.4.29, 7.3.7 or later.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-3rg7-wf37-54rm");

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

if (version_is_less(version: version, test_version: "5.4.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.50", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.4.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
