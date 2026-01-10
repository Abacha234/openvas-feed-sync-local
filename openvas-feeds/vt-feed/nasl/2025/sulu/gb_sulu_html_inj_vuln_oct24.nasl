# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sulu:sulu";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124596");
  script_version("2026-01-09T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-09 05:47:51 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"creation_date", value:"2025-12-03 15:35:34 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 14:23:38 +0000 (Tue, 08 Oct 2024)");

  script_cve_id("CVE-2024-47617");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sulu XSS Vulnerability (GHSA-6784-9c82-vr85)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sulu_http_detect.nasl");
  script_mandatory_keys("sulu/detected");

  script_tag(name:"summary", value:"Sulu is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability allows an attacker to inject arbitrary
  HTML/JavaScript code through the media download URL in Sulu CMS.");

  script_tag(name:"impact", value:"Potentially allow attackers to steal sensitive information,
  manipulate the website's content, or perform actions on behalf of the victim.");

  script_tag(name:"affected", value:"Sulu version 2.0.x prior to 2.5.21 and 2.6.x prior to 2.6.5.");

  script_tag(name:"solution", value:"Update to version 2.5.21, 2.6.5 or later.");

  script_xref(name:"URL", value:"https://github.com/sulu/sulu/security/advisories/GHSA-6784-9c82-vr85");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.5.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.21");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.6.0", test_version_up: "2.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
