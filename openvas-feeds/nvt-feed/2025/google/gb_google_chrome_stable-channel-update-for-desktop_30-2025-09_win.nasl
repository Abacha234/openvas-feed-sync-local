# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836697");
  script_version("2025-10-07T05:38:31+0000");
  script_cve_id("CVE-2025-11205", "CVE-2025-11206", "CVE-2025-11207", "CVE-2025-11208",
                "CVE-2025-11209", "CVE-2025-11210", "CVE-2025-11211", "CVE-2025-11212",
                "CVE-2025-11213", "CVE-2025-11215", "CVE-2025-11216", "CVE-2025-11219");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-06 15:38:59 +0530 (Mon, 06 Oct 2025)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_30-2025-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and conduct denial of service attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  141.0.7390.54 on Windows");

  script_tag(name: "solution", value:"Update to version 141.0.7390.54/55 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/09/stable-channel-update-for-desktop_30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"141.0.7390.54")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"141.0.7390.54/55", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
