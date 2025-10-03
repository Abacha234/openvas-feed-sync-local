# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155515");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-01 05:10:04 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-54477");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! User Enumeration Vulnerability (20250902)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to a user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper handling of authentication requests lead to a user
  enumeration vector in the passkey authentication method.");

  script_tag(name:"affected", value:"Joomla! version 4.0.0 through 4.4.13 and 5.0.0 through
  5.3.3.");

  script_tag(name:"solution", value:"Update to version 4.4.14, 5.3.4 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1011-20250902-core-user-enumeration-in-passkey-authentication-method.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
