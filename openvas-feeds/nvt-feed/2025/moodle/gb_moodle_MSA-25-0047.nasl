# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136303");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-22 07:31:44 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2025-62398");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.4.11, 4.5.x < 4.5.7, 5.x < 5.0.3 MFA Bypass Vulnerability (MSA-25-0047)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a multi-factor-authentication (MFA) bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect handling of some endpoints during login made it
  possible to bypass the second factor of multi-factor authentication. Note: A valid username and
  password were still required to log in.");

  script_tag(name:"affected", value:"Moodle version 4.4 through 4.4.10, 4.5.0 through 4.5.6 and 5.0
  through 5.0.2");

  script_tag(name:"solution", value:"Update to version 4.4.11, 4.5.7, 5.0.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470387");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5.0", test_version_up: "4.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}



exit(99);
