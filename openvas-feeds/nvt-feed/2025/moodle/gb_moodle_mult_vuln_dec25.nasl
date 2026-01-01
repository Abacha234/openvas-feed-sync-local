# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136751");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-22 11:45:41 +0000 (Mon, 22 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2025-67847", "CVE-2025-67848", "CVE-2025-67850", "CVE-2025-67851",
                "CVE-2025-67582", "CVE-2025-67853", "CVE-2025-67854", "CVE-2025-67855",
                "CVE-2025-67856", "CVE-2025-67857");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Multiple Vulnerabilities (Dec 25)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-67847 / MSA-25-0051: A remote code execution risk was identified in the file restore
  functionality.

  - CVE-2025-67848 / MSA-25-0052: Suspended users were not prevented from authenticating via the
  LTI Provider.

  - CVE-2025-67850 / MSA-25-0054: Insufficient sanitizing in the formula editor could result in an
  XSS risk.

  - CVE-2025-67851 / MSA-25-0055: Insufficient sanitizing when exporting data to CSV / XLSX format
  could result in malicious formulas being inserted into the files.

  - CVE-2025-67852 / MSA-25-0056: An open redirect risk existed in the OAuth login functionality.

  - CVE-2025-67853 / MSA-25-0057: Insufficient checks on a confirmation email web service made it
  easier to brute force password checks against known usernames.

  - CVE-2025-67854 / MSA-25-0058: Forum ratings required additional permission checks to prevent
  users from being able to view ratings they did not have the capability to access.

  - CVE-2025-67855 / MSA-25-0059: The return URL in the policy tool required extra sanitizing to
  prevent a reflected XSS risk.

  - CVE-2025-67856 / MSA-25-0060: Badges being awarded with a role performed the correct capability
  check, but did not verify the user had the required role to meet the award criterion.

  - CVE-2025-67857 / MSA-25-0061: When blind marking is enabled for an assignment, user IDs
  remained visible on the assignment submissions page instead of being masked.");

  script_tag(name:"affected", value:"Moodle versions prior to 4.1.21, 4.4.x through 4.4.11,
  4.5.x through 4.5.7, 5.0.x through 5.0.3, 5.1.");

  script_tag(name:"solution", value:"Update to version 4.1.22, 4.4.12, 4.5.8, 5.0.4, 5.1
  or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471297&parent=1892199");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471298&parent=1892200");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471300&parent=1892202");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471301&parent=1892203");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471302&parent=1892204");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471303&parent=1892205");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471304&parent=1892206");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471305&parent=1892207");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471306&parent=1892208");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=471307&parent=1892209");

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

if (version_is_less(version: version, test_version: "4.1.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5.0", test_version_up: "4.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
