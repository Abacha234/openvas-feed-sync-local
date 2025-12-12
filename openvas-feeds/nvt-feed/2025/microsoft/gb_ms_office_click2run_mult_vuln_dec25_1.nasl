# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.837000");
  script_version("2025-12-11T05:46:19+0000");
  script_cve_id("CVE-2025-62555", "CVE-2025-62558", "CVE-2025-62559", "CVE-2025-62553",
                "CVE-2025-62556", "CVE-2025-62560", "CVE-2025-62561", "CVE-2025-62563",
                "CVE-2025-62564", "CVE-2025-62562", "CVE-2025-62552", "CVE-2025-62554",
                "CVE-2025-62557");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-09 18:16:02 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-10 05:56:14 +0000 (Wed, 10 Dec 2025)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Dec 2025)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Office Click-to-Run update December 2025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to conduct
  remote code execution.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
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

## Version 2511 (Build 19426.20186)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.19426.20186"))
    fix = "Version 2511 (Build 19426.20186)";
}

## Semi-Annual Enterprise Channel: Version 2502 (Build 18526.20672)
## Semi-Annual Enterprise Channel: Version 2408 (Build 17928.20742)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.17928.0", test_version2:"16.0.17928.20741")) {
      fix = "Version 2408 (Build 17928.20742)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18526.0", test_version2:"16.0.18526.20671")) {
      fix = "Version 2502 (Build 18526.20672)";
  }
}

## Monthly Enterprise Channel: Version 2510 (Build 19328.20266)
## Monthly Enterprise Channel: Version 2509 (Build 19231.20274)
## Monthly Enterprise Channel: Version 2508 (Build 19127.20402)
else if(UpdateChannel == "Monthly Channel (Targeted)") {
  if(version_in_range(version:officeVer, test_version:"16.0.19127.0", test_version2:"16.0.19127.20401")) {
    fix = "Version 2508 (Build 19127.20402)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.19231.0", test_version2:"16.0.19231.20273")) {
    fix = "Version 2509 (Build 19231.20274)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.19328.0", test_version2:"16.0.19328.20265")) {
    fix = "Version 2510 (Build 19328.20266)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
