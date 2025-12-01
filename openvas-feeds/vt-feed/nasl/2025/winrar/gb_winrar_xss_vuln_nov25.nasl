# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rarlab:winrar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836861");
  script_version("2025-11-19T05:40:23+0000");
  script_cve_id("CVE-2025-52331");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-17 16:56:54 +0530 (Mon, 17 Nov 2025)");
  script_name("RARLabs WinRAR XSS Vulnerability (Nov 2025) - Windows");

  script_tag(name:"summary", value:"WinRAR is prone to a cross-site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to disclose user information such as the computer username, generated report
  directory and IP address.");

  script_tag(name:"affected", value:"RARLabs WinRAR version 7.11 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.12 beta 1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://gist.github.com/MarcinB44/2150484497c4b34aedf682c9091b14fa");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"7.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.12 beta 1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);