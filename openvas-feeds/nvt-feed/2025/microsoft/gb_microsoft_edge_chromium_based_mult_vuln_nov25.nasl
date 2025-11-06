# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836803");
  script_version("2025-11-05T05:40:07+0000");
  script_cve_id("CVE-2025-12441", "CVE-2025-12440", "CVE-2025-12439", "CVE-2025-12438",
                "CVE-2025-12437", "CVE-2025-12436", "CVE-2025-12435", "CVE-2025-12434",
                "CVE-2025-12036", "CVE-2025-12433", "CVE-2025-12432", "CVE-2025-12431",
                "CVE-2025-12430", "CVE-2025-12429", "CVE-2025-12428", "CVE-2025-12447",
                "CVE-2025-12446", "CVE-2025-12445", "CVE-2025-12444", "CVE-2025-60711",
                "CVE-2025-12443");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-11-05 05:40:07 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-31 20:15:52 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-11-03 17:29:49 +0530 (Mon, 03 Nov 2025)");
  script_name("Microsoft Edge (Chromium-Based) < 142.0.3595.53 Multiple Vulnerabilities (Nov 2025)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and conduct denial of service attacks.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 142.0.3595.53.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"142.0.3595.53")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"142.0.3595.53", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);