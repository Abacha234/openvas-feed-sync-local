# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155509");
  script_version("2025-10-03T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-10-03 05:38:37 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-01 04:08:40 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-9230");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20250930, CVE-2025-9230) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability due
  to a out-of-bounds read & write in RFC 3211 KEK Unwrap.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An application trying to decrypt CMS messages encrypted using
  password based encryption can trigger an out-of-bounds read and write.");

  script_tag(name:"impact", value:"This out-of-bounds read may trigger a crash which leads to
  denial of service for an application. The out-of-bounds write can cause a memory corruption which
  can have various consequences including a denial of service or execution of attacker-supplied
  code.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1, 3.0, 3.2, 3.3, 3.4 and 3.5.

  Notes:

  - The FIPS modules in 3.5, 3.4, 3.3, 3.2, 3.1 and 3.0 are not affected by this issue, as the CMS
  implementation is outside the OpenSSL FIPS module boundary

  - The EOL version 3.1.x is assumed to be affected as well");

  script_tag(name:"solution", value:"Update to version 1.0.2zm, 1.1.1zd, 3.0.18, 3.2.6, 3.3.5,
  3.4.3, 3.5.4 or later.");

  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20250930.txt");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zm")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zm", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1zd")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1zd", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0", test_version_up: "3.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1", test_version_up: "3.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.3", test_version_up: "3.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.4", test_version_up: "3.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.5", test_version_up: "3.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
