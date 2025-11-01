# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155510");
  script_version("2025-10-03T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-10-03 05:38:37 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-01 04:10:34 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2025-9231");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Timing Side-Channel Vulnerability (20250930, CVE-2025-9231) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a timing side-channel vulnerability in SM2
  algorithm on 64 bit ARM.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A timing side-channel which could potentially allow remote
  recovery of the private key exists in the SM2 algorithm implementation on 64 bit ARM
  platforms.");

  script_tag(name:"impact", value:"A timing side-channel in SM2 signature computations on 64 bit
  ARM platforms could allow recovering the private key by an attacker.");

  script_tag(name:"affected", value:"OpenSSL version 3.2, 3.3, 3.4 and 3.5.

  Note: The FIPS modules in 3.5, 3.4, 3.3, 3.2, 3.1 and 3.0 are not affected by this issue, as SM2
  is not an approved algorithm.");

  script_tag(name:"solution", value:"Update to version 3.2.6, 3.3.5, 3.4.3, 3.5.4 or later.");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.2", test_version_up: "3.2.6")) {
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
