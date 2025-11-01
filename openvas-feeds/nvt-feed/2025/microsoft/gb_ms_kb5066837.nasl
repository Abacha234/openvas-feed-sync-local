# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836716");
  script_version("2025-10-17T18:17:07+0000");
  script_cve_id("CVE-2025-59203", "CVE-2025-58739", "CVE-2025-59253", "CVE-2025-59244",
                "CVE-2025-59190", "CVE-2025-59278", "CVE-2025-59230", "CVE-2025-59205",
                "CVE-2025-59192", "CVE-2025-59275", "CVE-2025-58738", "CVE-2025-47827",
                "CVE-2025-59214", "CVE-2025-59197", "CVE-2025-59208", "CVE-2025-58736",
                "CVE-2025-58734", "CVE-2025-58715", "CVE-2025-59209", "CVE-2025-59198",
                "CVE-2025-59187", "CVE-2025-58733", "CVE-2025-58730", "CVE-2025-58729",
                "CVE-2025-58726", "CVE-2025-58725", "CVE-2025-58718", "CVE-2025-58714",
                "CVE-2025-55699", "CVE-2025-55695", "CVE-2025-55692", "CVE-2025-55678",
                "CVE-2025-55328", "CVE-2025-53768", "CVE-2025-50152", "CVE-2025-25004",
                "CVE-2016-9535", "CVE-2025-59295", "CVE-2025-59294", "CVE-2025-59282",
                "CVE-2025-59280", "CVE-2025-59277", "CVE-2025-59259", "CVE-2025-54957",
                "CVE-2025-59254", "CVE-2025-59242", "CVE-2025-59211", "CVE-2025-59201",
                "CVE-2025-59200", "CVE-2025-59196", "CVE-2025-59185", "CVE-2025-58735",
                "CVE-2025-58732", "CVE-2025-58717", "CVE-2025-58716", "CVE-2025-55701",
                "CVE-2025-55700", "CVE-2025-55687", "CVE-2025-55338", "CVE-2025-55335",
                "CVE-2025-55333", "CVE-2025-55325", "CVE-2025-24052", "CVE-2025-24990");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-10-17 18:17:07 +0000 (Fri, 17 Oct 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-23 15:04:25 +0000 (Wed, 23 Nov 2016)");
  script_tag(name:"creation_date", value:"2025-10-15 09:40:01 +0530 (Wed, 15 Oct 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5066837)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5066837");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5066837");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0) {
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

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.21160")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.21160");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);