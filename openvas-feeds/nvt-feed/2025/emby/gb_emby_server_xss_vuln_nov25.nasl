# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emby:emby.releases";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133118");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-19 06:38:49 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2025-64325");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Emby Server < 4.8.1.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_emby_server_http_detect.nasl");
  script_mandatory_keys("emby/media_server/detected");

  script_tag(name:"summary", value:"Emby Server is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A malicious user can send an authentication request with a
  manipulated 'X-Emby-Client' value, which gets added to the devices section of the admin dashboard
  without sanitization.");

  script_tag(name:"impact", value:"Possible remote code execution (RCE) through XSS in admin
  dashboard.");

  script_tag(name:"affected", value:"Emby Server prior to version 4.8.1.0.");

  script_tag(name:"solution", value:"Update to version 4.8.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/EmbySupport/Emby.Security/security/advisories/GHSA-2gwc-988r-2r7x");

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

if (version_is_less(version: version, test_version: "4.8.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
