# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119198");
  script_version("2025-10-24T05:39:31+0000");
  script_tag(name:"last_modification", value:"2025-10-24 05:39:31 +0000 (Fri, 24 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-22 14:59:24 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-21 20:20:43 +0000 (Tue, 21 Oct 2025)");

  script_cve_id("CVE-2025-53054", "CVE-2025-53053", "CVE-2025-53044", "CVE-2025-53045",
                "CVE-2025-53062", "CVE-2025-53069", "CVE-2025-53040", "CVE-2025-53042");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 8.0.43, 8.1.x <= 8.4.7, 9.0.0 <= 9.4.0 Security Update (cpuoct2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 8.0.43 and prior, 8.1.x through
  8.4.6 and 9.0.0 through 9.4.0.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it
  is assumed that all versions prior to 8.x and versions like 9.2.x in between are also affected by
  these flaws. If you disagree with this assessment and want to accept the risk please create an
  override for this result.");

  script_tag(name:"solution", value:"Update to version 8.0.44, 8.4.7, 9.4.1 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2025.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2025");

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

if (version_is_less_equal(version: version, test_version: "8.0.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.44", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1.0", test_version2: "8.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
