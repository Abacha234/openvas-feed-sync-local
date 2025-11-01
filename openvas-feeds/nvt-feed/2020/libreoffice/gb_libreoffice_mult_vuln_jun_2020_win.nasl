# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817256");
  script_version("2025-10-29T05:40:29+0000");
  script_cve_id("CVE-2020-12802", "CVE-2020-12803");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 00:15:00 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-03 12:54:56 +0530 (Mon, 03 Aug 2020)");
  script_name("LibreOffice Multiple Vulnerabilities (Jun 2020) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error exists while loading remote graphics links from docx documents.

  - An error in ODF documents.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to overwrite local files and disclose sensitive information.");

  script_tag(name:"affected", value:"LibreOffice before version 6.4.4.");

  script_tag(name:"solution", value:"Update to version 6.4.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2020-12802");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2020-12803");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_libreoffice_smb_login_detect.nasl",
                      "gb_libreoffice_portable_wmi_login_detect.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.4.4")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.4.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
