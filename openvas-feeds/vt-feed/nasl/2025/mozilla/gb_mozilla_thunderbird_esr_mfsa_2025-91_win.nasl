# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836865");
  script_version("2025-11-19T05:40:23+0000");
  script_cve_id("CVE-2025-13012", "CVE-2025-13016", "CVE-2025-13017", "CVE-2025-13018",
                "CVE-2025-13019", "CVE-2025-13013", "CVE-2025-13020", "CVE-2025-13014",
                "CVE-2025-13015");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-17 16:56:54 +0530 (Mon, 17 Nov 2025)");
  script_name("Mozilla Thunderbird ESR Security Update (mfsa_2025-91) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, bypass security restrictions and conduct
  spoofing attacks.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird ESR prior to version
  140.5 on Windows.");

  script_tag(name: "solution" , value:"Update to version 140.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-91/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"140.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"140.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);