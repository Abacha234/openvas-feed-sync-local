# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155797");
  script_version("2025-11-18T05:39:54+0000");
  script_tag(name:"last_modification", value:"2025-11-18 05:39:54 +0000 (Tue, 18 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-17 04:57:12 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-12817", "CVE-2025-12818");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL Multiple Vulnerabilities (Nov 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-12817: CREATE STATISTICS does not check for schema CREATE privilege

  - CVE-2025-12818: libpq undersizes allocations, via integer wraparound");

  script_tag(name:"affected", value:"PostgreSQL prior to version 13.23, 14.x prior to 14.20, 15.x
  prior to 15.15, 16.x prior to 16.11, 17.x prior to 17.7 and 18.x prior to 18.1.");

  script_tag(name:"solution", value:"Update to version 13.23, 14.20, 15.15, 16.11, 17.7, 18.1 or
  later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-181-177-1611-1515-1420-and-1323-released-3171/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-12817/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-12818/");

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

if (version_is_less(version: version, test_version: "13.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "17.0", test_version_up: "17.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
