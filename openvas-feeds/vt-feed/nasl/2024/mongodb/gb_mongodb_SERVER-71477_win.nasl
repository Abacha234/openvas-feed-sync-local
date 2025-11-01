# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128054");
  script_version("2025-09-23T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-09-23 05:39:06 +0000 (Tue, 23 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-09-19 10:00:00 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-22 18:39:20 +0000 (Mon, 22 Sep 2025)");

  script_cve_id("CVE-2024-8654");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Certificate Validation Vulnerability (SERVER-71477) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MongoDB Server may access non-initialized region of memory
  leading to unexpected behaviour when zero arguments are called in internal aggregation stage.");

  script_tag(name:"affected", value:"MongoDB version 6.0.0 through 6.0.3.");

  script_tag(name:"solution", value:"Update to version 6.0.4, 6.1.1 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-71477");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.4, 6.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
