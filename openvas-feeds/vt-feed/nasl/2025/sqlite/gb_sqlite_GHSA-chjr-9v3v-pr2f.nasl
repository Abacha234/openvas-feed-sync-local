# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136443");
  script_version("2025-11-04T05:40:22+0000");
  script_tag(name:"last_modification", value:"2025-11-04 05:40:22 +0000 (Tue, 04 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-03 14:52:21 +0000 (Mon, 03 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2025-52099");

  script_name("SQLite <= 3.50 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow vulnerability allows a remote attacker to
  cause a denial of service via the setupLookaside function.");

  script_tag(name:"affected", value:"SQLite version 3.50.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 03rd November, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/SCREAMBBY/CVE-2025-52099");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-chjr-9v3v-pr2f");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "3.50.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
