# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

#  Ref: LSS Security

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15484");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2004-1602");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD < 1.2.11 User Enumeration Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to a user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to determine which user names are valid on the
  remote host based on timing analysis attack of the login procedure.");

  script_tag(name:"impact", value:"An attacker may use this flaw to set up a list of valid
  usernames for a more efficient brute-force attack against the remote host.");

  script_tag(name:"solution", value:"Update to version 1.2.11 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11430");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.11");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
