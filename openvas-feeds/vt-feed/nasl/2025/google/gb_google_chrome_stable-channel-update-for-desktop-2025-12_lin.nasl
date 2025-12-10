# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836881");
  script_version("2025-12-09T05:47:47+0000");
  script_cve_id("CVE-2025-13630", "CVE-2025-13631", "CVE-2025-13632", "CVE-2025-13633",
                "CVE-2025-13634", "CVE-2025-13720", "CVE-2025-13721", "CVE-2025-13635",
                "CVE-2025-13636", "CVE-2025-13637", "CVE-2025-13638", "CVE-2025-13639",
                "CVE-2025-13640");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-12-09 05:47:47 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 19:16:17 +0000 (Thu, 04 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-03 17:31:38 +0530 (Wed, 03 Dec 2025)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2025-12) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to perform privilege escalation, run arbitrary code, bypass security
  restrictions, conduct spoofing and denial of service attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  143.0.7499.40 on Linux");

  script_tag(name: "solution", value:"Update to version 143.0.7499.40 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/12/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"143.0.7499.40")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"143.0.7499.40", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
