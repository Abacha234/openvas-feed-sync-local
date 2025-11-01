# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836752");
  script_version("2025-10-17T18:17:07+0000");
  script_cve_id("CVE-2025-25004");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-10-17 18:17:07 +0000 (Fri, 17 Oct 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-14 17:15:39 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-16 10:15:19 +0530 (Thu, 16 Oct 2025)");
  script_name("Microsoft PowerShell Elevation of Privilege Vulnerability (Oct 2025) - Windows");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2025-25004.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges.");

  script_tag(name:"affected", value:"PowerShell Core version 7.4 prior to 7.4.13
  and 7.5 prior to 7.5.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.4.13 or 7.5.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25004");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^7\.2" && version_is_less(version:vers, test_version:"7.4.13")) {
  fix = "7.4.13";
}
else if(vers =~ "^7\.3" && version_is_less(version:vers, test_version:"7.5.4")) {
  fix = "7.5.4";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);