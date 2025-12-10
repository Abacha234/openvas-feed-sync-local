# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openvpn:openvpn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836883");
  script_version("2025-12-09T05:47:47+0000");
  script_cve_id("CVE-2025-13751");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-12-09 05:47:47 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-03 17:31:38 +0530 (Wed, 03 Dec 2025)");
  script_name("OpenVPN DoS Vulnerability (Dec 2025) - Windows");

  script_tag(name:"summary", value:"OpenVPN is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service attacks.");

  script_tag(name:"affected", value:"OpenVPN version 2.6.0 through 2.6.16.");

  script_tag(name:"solution", value:"Update to version 2.6.17 or 2.7_rc3 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://community.openvpn.net/Security%20Announcements/CVE-2025-13751");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openvpn_win_detect.nasl");
  script_mandatory_keys("OpenVPN/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location (cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "2.6.0", test_version2: "2.6.16")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.6.17 or 2.7_rc3", install_path = path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);