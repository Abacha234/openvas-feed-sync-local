# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piriform:ccleaner_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811780");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-09-19 13:28:32 +0530 (Tue, 19 Sep 2017)");

  script_cve_id("CVE-2017-20201");

  script_name("CCleaner Cloud 'CCleaner.exe' Backdoor Trojan Vulnerability - Windows");

  script_tag(name:"summary", value:"CCleaner Cloud agent is prone to backdoor trojan installation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Contains a malicious pre-entry-point loader that diverts
  execution from __scrt_common_main_seh into a custom loader. That loader decodes an embedded blob
  into shellcode, allocates executable heap memory, resolves Windows API functions at runtime, and
  transfers execution to an in-memory payload. The payload performs anti-analysis checks, gathers
  host telemetry, encodes the data with a two-stage obfuscation, and attempts HTTPS exfiltration to
  hard-coded C2 servers or month-based DGA domains.");

  script_tag(name:"impact", value:"Potential impacts include remote data collection and
  exfiltration, stealthy in-memory execution and persistence, and potential lateral movement.");

  script_tag(name:"affected", value:"CCleaner Cloud Agent version 1.07.3191");

  script_tag(name:"solution", value:"Update to version 1.7.0.3214 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html");
  script_xref(name:"URL", value:"http://www.piriform.com/news/blog/2017/9/18/security-notification-for-ccleaner-v5336162-and-ccleaner-cloud-v1073191-for-32-bit-windows-users");
  script_xref(name:"URL", value:"https://blog.avast.com/progress-on-ccleaner-investigation");
  script_xref(name:"URL", value:"https://www.crowdstrike.com/en-us/blog/protecting-software-supply-chain-deep-insights-ccleaner-backdoor/");
  script_xref(name:"URL", value:"https://www.morphisec.com/blog/morphisec-discovers-ccleaner-backdoor/");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/ccleaner-and-ccleaner-cloud-malicious-backdoor-supply-chain-compromise");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ccleaner_cloud_agent_detect_win.nasl");
  script_mandatory_keys("CCleaner/Cloud/Win/Ver");
  script_xref(name:"URL", value:"https://www.piriform.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");

## Only 32-bit platform is affected
if((!os_arch) || ("x86" >!< os_arch)){
  exit(0);
}

if(!ccVer = get_app_version(cpe:CPE)){
  exit(0);
}

## 1.07.3191 = 1.7.0.3191
if(ccVer == "1.7.0.3191")
{
  report = report_fixed_ver(installed_version:ccVer, fixed_version:"1.7.0.3214");
  security_message(data:report);
  exit(0);
}
exit(0);
