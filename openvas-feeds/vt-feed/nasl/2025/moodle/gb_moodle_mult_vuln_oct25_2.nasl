# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136300");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-22 07:31:44 +0000 (Wed, 22 Oct 2025)");
  # using CVE-2025-62396, since it likely doesn't require authentication
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-62394", "CVE-2025-62396");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.5.x < 4.5.7, 5.x < 5.0.3 Multiple Vulnerabilities (MSA-25-0043, MSA-25-0045)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-62394 / MSA-25-0043: Insufficient enrolment checks could result in quiz notifications
  being sent to users who had an inactive enrolment in the course (such as being suspended or past
  their enrolment end date).

  - CVE-2025-62396 / MSA-25-0045: Incorrect error handling in the routing system could result in
  the application directories being listed if the 'Accept text/html' header was not configured.");

  script_tag(name:"affected", value:"Moodle versions 4.5.0 through 4.5.6, 5.0.0 through 5.0.2");

  script_tag(name:"solution", value:"Update to version 4.5.7, 5.0.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470383");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470385");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.5.0", test_version_up: "4.5.7.")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
