# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836827");
  script_version("2025-11-14T05:39:48+0000");
  script_cve_id("CVE-2025-60728", "CVE-2025-62201", "CVE-2025-62202", "CVE-2025-62199",
                "CVE-2025-60724");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-11 18:15:41 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 05:24:45 +0000 (Wed, 12 Nov 2025)");
  script_name("Microsoft Office Multiple Vulnerabilities (Nov 2025) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office on Mac OSX according to Microsoft security
  update November 2025");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution and information disclosure.");

  script_tag(name:"affected", value:"Microsoft Office 2021, 2024 prior to version 16.103 (Build 25110922).");

  script_tag(name:"solution", value:"Update to version 16.103 or later.");

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
  if(version_in_range(version:vers, test_version:"16.53.0", test_version2:"16.102.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.103 (Build 25110922)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
