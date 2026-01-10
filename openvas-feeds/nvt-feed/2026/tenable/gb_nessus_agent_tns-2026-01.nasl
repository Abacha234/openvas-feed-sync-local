# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136800");
  script_version("2026-01-09T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-09 05:47:51 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-08 16:02:40 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-36640");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent Privilege Escalation Vulnerability (TNS-2026-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_tenable_nessus_agent_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_agent/smb-login/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Installation/uninstallation of the Nessus Agent Tray App on
  Windows Hosts could lead to escalation of privileges.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 10.9.3 and 11.0.x
  through 11.0.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 10.9.4, 11.0.3 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2026-01");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.9.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
