# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125499");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-14 15:15:09 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2025-13080", "CVE-2025-13081", "CVE-2025-13082", "CVE-2025-13083");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Multiple Vulnerabilities (SA-CORE-2025-005 - SA-CORE-2025-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/detected");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-13080: HTTP request attributes can be overridden leading to cache poisoning.

  - CVE-2025-13081: Gadget chain methods exploitable for remote code execution when
  combined with insecure deserialization.

  - CVE-2025-13082: Malicious URLs can be crafted to perform site defacement.

  - CVE-2025-13083: Private and temporary files may be served with public cache headers
  leading to information disclosure.");

  script_tag(name:"affected", value:"Drupal version 8.x prior to 10.4.9, 10.5.x prior to 10.5.6,
  11.0.x prior to 11.1.9, and 11.2.x prior to 11.2.8.");

  script_tag(name:"solution", value:"Update to version 10.4.9, 10.5.6, 11.1.9, 11.2.8 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-005");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-006");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-007");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-008");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "10.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.2.0", test_version_up: "11.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
