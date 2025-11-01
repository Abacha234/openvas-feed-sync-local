# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:7-zip:7-zip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836710");
  script_version("2025-10-15T05:39:06+0000");
  script_cve_id("CVE-2025-55188");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-13 16:21:23 +0530 (Mon, 13 Oct 2025)");
  script_name("7-Zip Arbitrary File Write Vulnerability (Oct 2025) - Windows");

  script_tag(name:"summary", value:"7zip is prone to an arbitrary file write
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform arbitrary file writes on target systems.");

  script_tag(name:"affected", value:"7zip prior to version 25.01 on Windows.");

  script_tag(name:"solution", value:"Update to version 25.01 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.7-zip.org/history.txt");
  script_xref(name:"URL", value:"https://lunbun.dev/blog/cve-2025-55188/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"25.01")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"25.01", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);