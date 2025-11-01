# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836794");
  script_version("2025-10-31T05:40:56+0000");
  script_cve_id("CVE-2025-12380");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-29 11:45:21 +0530 (Wed, 29 Oct 2025)");
  script_name("Mozilla Firefox Security Update (mfsa_2025-86) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to an use after free
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to escape the browser's sandbox and execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version 142 through 144.0.1
  on Windows.");

  script_tag(name:"solution", value:"Update to version 144.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-86/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"142.0", test_version_up:"144.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"144.0.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);