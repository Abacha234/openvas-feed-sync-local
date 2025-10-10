# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836695");
  script_version("2025-10-09T05:39:13+0000");
  script_cve_id("CVE-2025-59802", "CVE-2025-59803");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-10-09 05:39:13 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-06 12:53:02 +0530 (Mon, 06 Oct 2025)");
  script_name("Foxit Reader Multiple Vulnerabilities (Oct 2025) - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to insert malicious content into signed documents, causing recipients to trust
  or approve forged documents and enabling fraud, unauthorized transactions, malware
  delivery, and serious reputational, legal, or financial harm.");

  script_tag(name:"affected", value:"Foxit Reader version 2025.2.0.33046 and
  prior on Windows.");

  script_tag(name:"solution", value:"Update to version 2025.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2025.2.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2025.2.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);