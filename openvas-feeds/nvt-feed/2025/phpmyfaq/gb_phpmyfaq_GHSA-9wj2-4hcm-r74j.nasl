# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124383");
  script_version("2025-10-10T15:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-10 15:40:56 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-08 12:08:56 +0200 (Wed, 08 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2025-59943");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ 4.0.7 < 4.0.13 Privilege Escalation Vulnerability (GHSA-9wj2-4hcm-r74j)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpMyFAQ does not enforce uniqueness of email addresses during
  user registration. This allows multiple distinct accounts to be created with the same email.
  Because email is often used as an identifier for password resets, notifications, and
  administrative actions, this flaw can cause account ambiguity and, in certain configurations,
  may lead to privilege escalation or account takeover.");

  script_tag(name:"affected", value:"phpMyFAQ version 4.0.7 prior to 4.0.13.");

  script_tag(name:"solution", value:"Update to version 4.0.13 or later.");

  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9wj2-4hcm-r74j");
  script_xref(name:"URL", value:"https://radar.offseq.com/threat/cve-2025-59943-cwe-286-incorrect-user-management-i-5f22e24f");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.7", test_version_up: "4.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
