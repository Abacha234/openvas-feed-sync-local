# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openvpn:openvpn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836871");
  script_version("2025-11-21T15:39:49+0000");
  script_cve_id("CVE-2025-13086");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-11-21 15:39:49 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-20 22:41:49 +0530 (Thu, 20 Nov 2025)");
  script_name("OpenVPN HMAC Verification Vulnerability Bypass (Nov 2025) - Windows");

  script_tag(name:"summary", value:"OpenVPN is prone to a hmac bypass verification
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to gain unauthorized access.");

  script_tag(name:"affected", value:"OpenVPN version 2.6.0 through 2.6.15.");

  script_tag(name:"solution", value:"Update to version 2.6.16 or 2.7_rc2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://community.openvpn.net/Security%20Announcements/CVE-2025-13086");
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

if(version_in_range(version: vers, test_version: "2.6.0", test_version2: "2.6.15")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.6.16 or 2.7_rc2", install_path = path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);