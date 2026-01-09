# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ui:unifi_protect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156095");
  script_version("2026-01-08T05:48:01+0000");
  script_tag(name:"last_modification", value:"2026-01-08 05:48:01 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-07 04:27:12 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2026-21633", "CVE-2026-21634");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("UniFi Protect < 6.2.72 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ui_unifi_protect_ubnt_detect.nasl");
  script_mandatory_keys("ui/unifi_protect/detected");

  script_tag(name:"summary", value:"UniFi Protect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2026-21633: A malicious actor with access to the adjacent network could obtain unauthorized
  access to a UniFi Protect Camera by exploiting a discovery protocol vulnerability.

  - CVE-2026-21634: A malicious actor with access to the adjacent network could overflow the UniFi
  Protect Application discovery protocol causing it to restart.");

  script_tag(name:"affected", value:"UniFi Protect version 6.1.79 and prior.");

  script_tag(name:"solution", value:"Update to version 6.2.72 or later.");

  script_xref(name:"URL", value:"https://community.ui.com/releases/Security-Advisory-Bulletin-058-058/6922ff20-8cd7-4724-8d8c-676458a2d0f9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.1.79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.72");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
