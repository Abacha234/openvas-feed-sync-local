# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836927");
  script_version("2025-12-18T05:46:55+0000");
  script_cve_id("CVE-2025-14714");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-16 15:03:13 +0530 (Tue, 16 Dec 2025)");
  script_name("Libre Office TCC Bypass via Bundled Interpreter vulnerability (Dec 2025) - Mac OS X");

  script_tag(name:"summary", value:"Libre Office is prone to a tcc bypass via bundled
  interpreter vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute scripts using LibreOffice's bundled Python interpreter that inherit
  the application's TCC permissions without user approval.");

  script_tag(name:"affected", value:"Libre Office prior to version 24.2.4 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 24.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2025-14714/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

libre_ver = infos["version"];
libre_path = infos["location"];

if(version_is_less(version:libre_ver, test_version:"24.2.4")) {
  report = report_fixed_ver(installed_version:libre_ver, fixed_version:"24.2.4", install_path:libre_path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
