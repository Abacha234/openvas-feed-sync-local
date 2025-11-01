# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103331");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-11-15 10:15:56 +0100 (Tue, 15 Nov 2011)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2011-4130");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD < 1.3.3g RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits will allow attackers to execute arbitrary
  code within the context of the application. Failed exploit attempts will result in a denial of
  service condition.");

  script_tag(name:"affected", value:"ProFTPD prior to version 1.3.3g.");

  script_tag(name:"solution", value:"Update to version 1.3.3g or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50631");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3711");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-328/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.3g")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.3g");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
