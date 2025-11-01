# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155513");
  script_version("2025-10-03T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-10-03 05:38:37 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-01 04:17:52 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-9232");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20250930, CVE-2025-9232) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability due
  to an out-of-bounds read in HTTP client no_proxy handling.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An application using the OpenSSL HTTP client API functions may
  trigger an out-of-bounds read if the 'no_proxy' environment variable is set and the host portion
  of the authority component of the HTTP URL is an IPv6 address.");

  script_tag(name:"impact", value:"An out-of-bounds read can trigger a crash which leads to denial
  of service for an application.");

  # nb: Advisory has:
  # > The vulnerable code was introduced in the following patch releases: 3.0.16, 3.1.8, 3.2.4,
  # 3.3.3, 3.4.0 and 3.5.0.
  script_tag(name:"affected", value:"OpenSSL version 3.0 starting from 3.0.16, 3.1 starting from
  3.1.8, 3.2 starting from 3.2.4, 3.3 starting from 3.3.3, 3.4 and 3.5.

  Note: The FIPS modules in 3.5, 3.4, 3.3, 3.2, 3.1 and 3.0 are not affected by this issue, as the
  HTTP client implementation is outside the OpenSSL FIPS module boundary.");

  script_tag(name:"solution", value:"Update to version 3.0.18, 3.2.6, 3.3.5, 3.4.3, 3.5.4 or
  later.");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.16", test_version_up: "3.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.8", test_version_up: "3.2") ||
    version_in_range_exclusive(version: version, test_version_lo: "3.2.4", test_version_up: "3.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.3.3", test_version_up: "3.3.5")) {
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
