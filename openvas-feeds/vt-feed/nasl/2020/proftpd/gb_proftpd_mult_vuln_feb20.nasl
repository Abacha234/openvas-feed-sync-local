# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113645");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-02-21 11:37:46 +0000 (Fri, 21 Feb 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-21 23:15:00 +0000 (Fri, 21 Feb 2020)");

  script_cve_id("CVE-2020-9272", "CVE-2020-9273");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD < 1.3.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - There is an out-of-bounds (OOB) read vulnerability in mod_cap via the cap_text.c cap_to_text
  function.

  - It is possible to corrupt the memory pool by interrupting the data transfer channel. This
  triggers a use-after-free in alloc_pool in pool.c.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read
  sensitive information or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"ProFTPD version 1.3.6 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.7 or later.");

  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/902");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/903");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit(0);

if( version_is_less( version: version, test_version: "1.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.7" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
