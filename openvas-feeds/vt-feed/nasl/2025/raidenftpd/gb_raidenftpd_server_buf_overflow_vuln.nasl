# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:raidenftpd:raidenftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.129017");
  script_version("2025-11-25T05:40:35+0000");
  script_tag(name:"last_modification", value:"2025-11-25 05:40:35 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-20 08:00:00 +0000 (Thu, 20 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-13 19:16:32 +0000 (Wed, 13 Sep 2023)");

  script_cve_id("CVE-2023-39063");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RaidenFTPD Server <= 2.4.4005 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_raidenftpd_server_smb_login_detect.nasl");
  script_mandatory_keys("RaidenFTPD/smb-login/detected");

  script_tag(name:"summary", value:"RaidenFTPD v.2.4 build 4005 allows a local attacker to execute
  arbitrary code via the Server name field of the step by step setup wizard.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability allows a local attacker to execute
  arbitrary code via the Server name field of the step by step setup wizard.");

  script_tag(name:"impact", value:"Successful exploitation may allows a local attacker to execute
  arbitrary code.");

  script_tag(name:"affected", value:"RaidenFTPD Server version 2.4.4005 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.4050 or later.");

  script_xref(name:"URL", value:"https://github.com/AndreGNogueira/CVE-2023-39063");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/51611");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "2.4.4005")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"2.4.4050", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);