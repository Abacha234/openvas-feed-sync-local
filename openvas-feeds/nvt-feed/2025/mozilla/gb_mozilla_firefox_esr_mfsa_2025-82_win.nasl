# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836768");
  script_version("2025-10-22T05:39:59+0000");
  script_cve_id("CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11714");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-17 10:39:30 +0530 (Fri, 17 Oct 2025)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2025-82) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to an integer
  overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution and disclose information.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.29 on Windows.");

  script_tag(name:"solution", value:"Update to version 115.29 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-82/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.29")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.29", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);