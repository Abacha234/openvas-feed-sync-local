# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125474");
  script_version("2025-11-07T15:43:15+0000");
  script_tag(name:"last_modification", value:"2025-11-07 15:43:15 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-07 08:12:11 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-25 14:15:43 +0000 (Thu, 25 Sep 2025)");

  script_cve_id("CVE-2025-10948");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 7.x Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability affects the function parse_json_element of the
  file /rest/ip/address/print of the component libjson.so. The manipulation leads to buffer
  overflow. The exploit has been disclosed to the public and may be used.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 7.x prior to 7.20.1 and 7.21.x
  prior to 7.21beta2.");

  script_tag(name:"solution", value:"Update to version 7.20.1, 7.21beta2 or later.");

  script_xref(name:"URL", value:"https://github.com/a2ure123/libjson-unicode-buffer-overflow-poc");
  script_xref(name:"URL", value:"https://github.com/a2ure123/libjson-unicode-buffer-overflow-poc#technical-proof-of-concept");
  script_xref(name:"URL", value:"https://vuldb.com/?ctiid.325818");
  script_xref(name:"URL", value:"https://vuldb.com/?id.325818");
  script_xref(name:"URL", value:"https://vuldb.com/?submit.652387");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.20.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.20.1");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.21beta[01]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.21beta2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
