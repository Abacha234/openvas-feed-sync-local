# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:qnap:video_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155543");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-06 03:53:38 +0000 (Mon, 06 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2024-56804");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Video Station SQLi Vulnerability (QSA-25-32)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_videostation_http_detect.nasl");
  script_mandatory_keys("qnap/videostation/detected");

  script_tag(name:"summary", value:"QNAP Video Station is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If a remote attacker gains access to a user account, they can
  then exploit the vulnerability to execute unauthorized code or commands.");

  script_tag(name:"affected", value:"QNAP Video Station version 5.8.x prior to 5.8.4.");

  script_tag(name:"solution", value:"Update to version 5.8.4 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-32");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.8.0", test_version_up: "5.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
