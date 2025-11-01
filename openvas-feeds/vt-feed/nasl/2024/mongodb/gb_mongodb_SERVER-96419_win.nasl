# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153445");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"creation_date", value:"2024-11-15 09:41:06 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-01 18:40:03 +0000 (Wed, 01 Oct 2025)");

  script_cve_id("CVE-2024-10921");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Buffer Over-Read Vulnerability (SERVER-96419) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a buffer over-read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authorized user may trigger crashes or receive the contents
  of buffer over-reads of Server memory by issuing specially crafted requests that construct
  malformed BSON in the MongoDB Server.");

  script_tag(name:"affected", value:"MongoDB version 5.0.x prior to 5.0.30, 6.0.x prior to 6.0.19,
  7.0.x prior to 7.0.15 and 8.0.x prior to 8.0.3.");

  script_tag(name:"solution", value:"Update to version 5.0.30, 6.0.19, 7.0.15, 8.0.3 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-96419");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.30");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.19");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.15");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
