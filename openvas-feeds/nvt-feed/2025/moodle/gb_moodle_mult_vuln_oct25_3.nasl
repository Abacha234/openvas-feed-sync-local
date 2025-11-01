# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136301");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-22 07:31:44 +0000 (Wed, 22 Oct 2025)");
  # based on CVE-2025-62399, the others have lower severity
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2025-54869", "CVE-2025-62395", "CVE-2025-62399", "CVE-2025-62400",
  "CVE-2025-62401");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.21, 4.4.x < 4.4.11, 4.5.x < 4.5.7, 5.x < 5.0.3 Multiple Vulnerabilities (MSA-25-0042, MSA-25-0044, MSA-25-0048, MSA-25-0049, MSA-25-0050)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-54869 / MSA-25-0042: The upstream FPDI library was upgraded, which included a security
  fix for a denial-of-service (DoS) vulnerability.

  - CVE-2025-62395 / MSA-25-0044: Insufficient capability checks meant a user with permission to
  manage/view cohorts in a lower context could retrieve data about cohorts defined in the system
  context, that they would not otherwise have access to.

  - CVE-2025-62399 / MSA-25-0048: It was possible to brute force password checks against known
  usernames when the mobile client and auth_webservice were enabled.

  - CVE-2025-62400 / MSA-25-0049: Insufficient capability checks meant users with the capability to
  create group events, but without the capability to view hidden groups, could see hidden and
  separate groups in the list of groups to select for calendar events.

  - CVE-2025-62401 / MSA-25-0050: There was a behaviour that made it possible for a student to
  bypass the timed restriction on a timed assignment.");

  script_tag(name:"affected", value:"Moodle version 4.1.0 through 4.1.20 and earlier unsupported
  versions, 4.4.0 through 4.4.10, 4.5.0 through 4.5.6, 5.0.0 through 5.0.2");

  script_tag(name:"solution", value:"Update to version 4.1.21, 4.4.11, 4.5.7, 5.0.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470382");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470384");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470388");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470389");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=470390");

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

if (version_is_less(version: version, test_version: "4.1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
