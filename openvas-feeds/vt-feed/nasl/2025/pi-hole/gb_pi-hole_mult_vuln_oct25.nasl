# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155704");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-06 01:58:46 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:P");

  script_cve_id("CVE-2025-59151", "CVE-2025-32785", "CVE-2024-57779", "CVE-2025-53533");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface < 6.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_consolidation.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-59151: Carriage return line feed (CRLF) injection leading to header injection, session
  fixation and HTTP response splitting

  - CVE-2025-32785: Persistent XSS on subscribed lists group management (address field)

  - CVE-2024-57779: Stored cross-site scripting (XSS)

  - CVE-2025-53533: Unauthenticated reflected XSS in 404-error page");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) prior to version
  6.3.");

  script_tag(name:"solution", value:"Update to version 6.3 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-5v79-p56f-x7c4");
  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-7w6h-3gwc-qhq5");
  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-8hr3-47jh-25vr");
  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-w8f8-92rx-4f6w");
  script_xref(name:"URL", value:"https://pi-hole.net/blog/2025/10/25/pi-hole-ftl-v6-3-web-v6-3-and-core-v6-2-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
