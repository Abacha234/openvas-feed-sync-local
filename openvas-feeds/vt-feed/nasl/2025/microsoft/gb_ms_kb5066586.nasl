# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836719");
  script_version("2025-10-17T18:17:07+0000");
  script_cve_id("CVE-2025-59253", "CVE-2025-59244", "CVE-2025-59214", "CVE-2025-59230",
                "CVE-2025-59278", "CVE-2025-59275", "CVE-2025-59205", "CVE-2025-58739",
                "CVE-2025-59193", "CVE-2025-59198", "CVE-2025-59191", "CVE-2025-47827",
                "CVE-2025-59197", "CVE-2025-58737", "CVE-2025-59209", "CVE-2025-59203",
                "CVE-2025-59190", "CVE-2025-59188", "CVE-2025-59187", "CVE-2025-59184",
                "CVE-2025-58736", "CVE-2025-58733", "CVE-2025-59280", "CVE-2025-59204",
                "CVE-2025-59200", "CVE-2025-58722", "CVE-2025-55700", "CVE-2025-55336",
                "CVE-2025-59287", "CVE-2025-59260", "CVE-2025-59208", "CVE-2025-59192",
                "CVE-2025-58738", "CVE-2025-58734", "CVE-2025-58730", "CVE-2025-58729",
                "CVE-2025-58726", "CVE-2025-58725", "CVE-2025-58720", "CVE-2025-58718",
                "CVE-2025-58714", "CVE-2025-55699", "CVE-2025-55696", "CVE-2025-55695",
                "CVE-2025-55692", "CVE-2025-55683", "CVE-2025-55680", "CVE-2025-55679",
                "CVE-2025-55678", "CVE-2025-55332", "CVE-2025-55328", "CVE-2025-55326",
                "CVE-2025-53768", "CVE-2025-50175", "CVE-2025-53150", "CVE-2025-50152",
                "CVE-2025-25004", "CVE-2025-48813", "CVE-2016-9535", "CVE-2025-59295",
                "CVE-2025-59294", "CVE-2025-59282", "CVE-2025-59277", "CVE-2025-59259",
                "CVE-2025-59258", "CVE-2025-54957", "CVE-2025-59255", "CVE-2025-59254",
                "CVE-2025-49708", "CVE-2025-59242", "CVE-2025-59211", "CVE-2025-59207",
                "CVE-2025-59202", "CVE-2025-59201", "CVE-2025-59199", "CVE-2025-59196",
                "CVE-2025-59195", "CVE-2025-59186", "CVE-2025-59185", "CVE-2025-58735",
                "CVE-2025-58732", "CVE-2025-58728", "CVE-2025-58719", "CVE-2025-58717",
                "CVE-2025-58716", "CVE-2025-58715", "CVE-2025-55701", "CVE-2025-55687",
                "CVE-2025-55681", "CVE-2025-55338", "CVE-2025-55335", "CVE-2025-55333",
                "CVE-2025-55325", "CVE-2025-24052", "CVE-2025-24990");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-10-17 18:17:07 +0000 (Fri, 17 Oct 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-14 17:15:42 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-15 09:40:01 +0530 (Wed, 15 Oct 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5066586)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5066586");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5066586");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0) {
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.7918")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.7918");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);