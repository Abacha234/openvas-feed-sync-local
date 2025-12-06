# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836879");
  script_version("2025-12-05T05:44:55+0000");
  script_cve_id("CVE-2023-21714", "CVE-2023-21715");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-17 18:52:41 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"creation_date", value:"2025-12-01 12:44:45 +0530 (Mon, 01 Dec 2025)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Feb 2023)");

  script_tag(name:"summary", value:"This host is missing a critical security update
  according to Microsoft Office Click-to-Run update February 2023.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to disclose information and bypass security restrictions.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#february-14-2023");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\.")
  exit(0);

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2301 (Build 16026.20200)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.16026.20200"))
    fix = "Version 2301 (Build 16026.20200)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2208 (Build 15601.20538)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.15601.20538"))
    fix = "Version 2208 (Build 15601.20538)";
}

## Semi-Annual Enterprise Channel: Version 2208 (Build 15601.20538)
## Semi-Annual Enterprise Channel: Version 2202 (Build 14931.20926)
## Semi-Annual Enterprise Channel: Version 2108 (Build 14326.21336)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.15601.0", test_version2:"16.0.15601.205367")) {
    fix = "Version 2208 (Build 15601.20538)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.14931.0", test_version2:"16.0.14931.20925")) {
      fix = "Version 2202 (Build 14931.20926)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.14326.0", test_version2:"16.0.14326.21335")) {
      fix = "Version 2108 (Build 14326.21336)";
  }
}

## Monthly Enterprise Channel: Version 2211 (Build 15831.20280)
## Monthly Enterprise Channel: Version 2212 (Build 15928.20282)
else if(UpdateChannel == "Monthly Channel (Targeted)") {
  if(version_in_range(version:officeVer, test_version:"16.0.18623.0", test_version2:"16.0.15928.20281")) {
    fix = "Version 2212 (Build 15928.20282)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.15831.0", test_version2:"16.0.15831.20279")) {
    fix = "Version 2211 (Build 15831.20280)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
