# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155905");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-01 07:33:12 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-51240");

  script_tag(name:"qod_type", value:"package_unreliable"); # nb: luci-mod-rpc package needs to installed

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("OpenWRT Privilege Escalation Vulnerability (Mar 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue in the luci-mod-rpc package allows for privilege
  escalation from an admin account to root via the JSON-RPC-API, which is exposed by the
  luci-mod-rpc package.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: OpenWRT has stated they will not address this vulnerability, instead planning to update
  their public documentation to clarify the deprecation status.");

  script_xref(name:"URL", value:"https://github.com/VitoCrl/vulnerability_research/tree/main/CVE-2024-51240");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

report = report_fixed_ver(installed_version: version, fixed_version: "None");
security_message(port: 0, data: report);
exit(0);
