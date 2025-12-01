# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:raidenftpd:raidenftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.129016");
  script_version("2025-11-25T05:40:35+0000");
  script_tag(name:"last_modification", value:"2025-11-25 05:40:35 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-20 08:00:00 +0000 (Thu, 20 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-21 19:05:59 +0000 (Mon, 21 Oct 2024)");

  script_cve_id("CVE-2023-38960");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("RaidenFTPD Server Insecure Permissions Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_raidenftpd_server_smb_login_detect.nasl");
  script_mandatory_keys("RaidenFTPD/smb-login/detected");

  script_tag(name:"summary", value:"RaidenFTPD Server v.2.4 build 4005 and greater allows a local
  attacker to gain privileges and execute arbitrary code via crafted executable running from the
  installation directory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper permission in the RaidenFTPD server folder and the
  executable files inside may allow a local, non-privileged user on a Windows host running
  RaidenFTPD v2.4 to escalate privileges via DLL hijacking or by replacing the executable used
  by the Windows service (for example, RaidenFTPDService or any service tied to this FTP server).
  Successful privilege escalation depends on whether the FTP server is run via the corresponding
  Windows service (e.g., RaidenFTPDService).");

  script_tag(name:"impact", value:"Successful exploitation may lead to complete compromise of the
  data hosted in the FTP server and the main Windows host.");

  script_tag(name:"affected", value:"RaidenFTPD Server version starting from 2.4.4005.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://rodelllemit.medium.com/insecure-permissions-vulnerability-in-raidenftpd-v2-4-build-4005-2016-04-01-ea7389be3d33");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: Advisory says "2.4.4005" but there is no fix available for over a year
# so ">= 2.4.4005" is used here without an upper bound
if (version_is_greater_equal(version: version, test_version: "2.4.4005")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);