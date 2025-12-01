# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836825");
  script_version("2025-11-14T05:39:48+0000");
  script_cve_id("CVE-2025-59240", "CVE-2025-60726", "CVE-2025-60727", "CVE-2025-60728",
                "CVE-2025-62200", "CVE-2025-62201", "CVE-2025-62202", "CVE-2025-62203",
                "CVE-2025-62199", "CVE-2025-62205", "CVE-2025-62216");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-11 18:15:49 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 05:24:45 +0000 (Wed, 12 Nov 2025)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Nov 2025)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Office Click-to-Run update November 2025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to conduct
  remote code execution and information disclosure.");

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

## Version 2510 (Build 19328.20190)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.19328.20190"))
    fix = "Version 2510 (Build 19328.20190)";
}

## Semi-Annual Enterprise Channel: Version 2502 (Build 18526.20660)
## Semi-Annual Enterprise Channel: Version 2408 (Build 17928.20730)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.17928.0", test_version2:"16.0.17928.20729")) {
      fix = "Version 2408 (Build 17928.20730)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18526.0", test_version2:"16.0.18526.20659")) {
      fix = "Version 2502 (Build 18526.20660)";
  }
}

## Monthly Enterprise Channel: Version 2509 (Build 19231.20246)
## Monthly Enterprise Channel: Version 2508 (Build 19127.20358)
## Monthly Enterprise Channel: Version 2507 (Build 19029.20294)
else if(UpdateChannel == "Monthly Channel (Targeted)") {
  if(version_in_range(version:officeVer, test_version:"16.0.19029.0", test_version2:"16.0.19029.20293")) {
    fix = "Version 2507 (Build 19029.20294)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.19127.0", test_version2:"16.0.19127.20357")) {
    fix = "Version 2508 (Build 19127.20358)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.19231.0", test_version2:"16.0.19231.20245")) {
    fix = "Version 2509 (Build 19231.20246)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
