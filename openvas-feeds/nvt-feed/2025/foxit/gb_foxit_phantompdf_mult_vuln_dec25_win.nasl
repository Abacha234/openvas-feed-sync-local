# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836939");
  script_version("2025-12-24T05:46:55+0000");
  script_cve_id("CVE-2025-57779", "CVE-2025-58085", "CVE-2025-59488", "CVE-2025-66493",
                "CVE-2025-66494", "CVE-2025-66495", "CVE-2025-13941", "CVE-2025-66496",
                "CVE-2025-66497", "CVE-2025-66498", "CVE-2025-66499");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-12-24 05:46:55 +0000 (Wed, 24 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-23 10:40:43 +0530 (Tue, 23 Dec 2025)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (Dec 2025) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to escalate privileges, execute arbitrary code and conduct denial of service attacks.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 2025.x through 2025.2.1.33197,
  2024.x through 2024.4.1.27687, 2023.x through 2023.3.0.23028, 14.x through 14.0.1.33197
  and prior to 13.2.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 2025.3 or 14.0.2 or 13.2.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"13.2.2") ||
   version_in_range(version:vers, test_version:"14.0", test_version2:"14.0.1.33197") ||
   version_in_range(version:vers, test_version:"2023", test_version2:"2023.3.0.23028") ||
   version_in_range(version:vers, test_version:"2024", test_version2:"2024.4.1.27687") ||
   version_in_range(version:vers, test_version:"2025", test_version2:"2025.2.1.33197")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2025.3/14.0.2/13.2.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);