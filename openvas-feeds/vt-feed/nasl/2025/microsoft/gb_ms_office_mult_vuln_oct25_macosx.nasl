# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836749");
  script_version("2025-10-30T05:40:01+0000");
  script_cve_id("CVE-2025-59221", "CVE-2025-59222", "CVE-2025-59223", "CVE-2025-59224",
                "CVE-2025-59225", "CVE-2025-59227", "CVE-2025-59231", "CVE-2025-59232",
                "CVE-2025-59233", "CVE-2025-59234", "CVE-2025-59235", "CVE-2025-59236");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-28 20:20:22 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-16 05:39:07 +0000 (Thu, 16 Oct 2025)");
  script_name("Microsoft Office Multiple Vulnerabilities (Oct 2025) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office on Mac OSX according to Microsoft security
  update October 2025");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution and information disclosure.");

  script_tag(name:"affected", value:"Microsoft Office 2021, 2024 prior to version 16.102 (Build 25101223).");

  script_tag(name:"solution", value:"Update to version 16.102 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("MS/Office/MacOSX/Ver"))
  exit(0);

if(vers =~ "^16\.") {
  if(version_in_range(version:vers, test_version:"16.53.0", test_version2:"16.101.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.102");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
