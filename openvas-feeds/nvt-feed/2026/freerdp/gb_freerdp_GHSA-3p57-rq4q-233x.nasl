# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124690");
  script_version("2026-01-09T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-09 05:47:51 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-08 07:00:11 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-14 20:39:08 +0000 (Tue, 14 Oct 2025)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2025-4478");

  script_name("FreeRDP DoS Vulnerability (GHSA-3p57-rq4q-233x)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the gnome-remote-desktop used by Anaconda's
  remote install feature, where a crafted RDP packet could trigger a segmentation fault.");

  script_tag(name:"impact", value:"This issue causes the service to crash and remain defunct,
  resulting in a denial of service. It occurs pre-boot and is likely due to a NULL pointer
  dereference. Rebooting is required to recover the system.");

  script_tag(name:"affected", value:"FreeRDP versions 3.x prior to 3.16.0.");

  script_tag(name:"solution", value:"Update to version 3.16.0 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-3p57-rq4q-233x");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/releases/tag/3.16.0");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/pull/11573");
  # nb: This comment includes the info that only 3.x versions are affected
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/pull/11573#issuecomment-2904160524");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"3.0", test_version_up:"3.16.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.16.0", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
