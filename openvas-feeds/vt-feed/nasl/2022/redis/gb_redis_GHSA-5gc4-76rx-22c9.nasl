# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118371");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2022-09-26 12:30:57 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-26 14:37:00 +0000 (Mon, 26 Sep 2022)");

  script_cve_id("CVE-2022-35951");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 7.0.x < 7.0.5 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_tcp_detect.nasl");
  script_mandatory_keys("redis/detected");

  script_tag(name:"summary", value:"Redis is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Executing a XAUTOCLAIM command on a stream key in a specific
  state, with a specially crafted COUNT argument, may cause an integer overflow, a subsequent heap
  overflow, and potentially lead to remote code execution.");

  script_tag(name:"affected", value:"Redis version 7.0.x prior to version 7.0.5.");

  script_tag(name:"solution", value:"Update to version 7.0.5 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.5");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-5gc4-76rx-22c9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range_exclusive( version:version, test_version_lo:"7.0.0", test_version_up:"7.0.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
