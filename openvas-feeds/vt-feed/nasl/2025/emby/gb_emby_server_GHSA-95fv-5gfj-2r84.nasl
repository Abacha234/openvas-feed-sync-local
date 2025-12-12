# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emby:emby.releases";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133146");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-10 07:48:49 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-64113");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Emby Server Improper Authentication Vulnerability (GHSA-95fv-5gfj-2r84)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_emby_server_http_detect.nasl");
  script_mandatory_keys("emby/media_server/detected");

  script_tag(name:"summary", value:"Emby Server is prone to an improper authentication
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows an attacker to gain full administrative access to an
  Emby Server (for Emby Server administration, not at the OS level).");

  script_tag(name:"affected", value:"Emby Server version 4.9.1.80 and prior.");

  script_tag(name:"solution", value:"Update to version 4.9.1.90 or later.");

  script_xref(name:"URL", value:"https://github.com/EmbySupport/Emby.Security/security/advisories/GHSA-95fv-5gfj-2r84");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.9.1.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.1.90", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
