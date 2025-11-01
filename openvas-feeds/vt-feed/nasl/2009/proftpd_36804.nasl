# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100316");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2009-3639");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD < 1.3.2b, 1.3.3 - 1.3.3.rc1 SSL Certificate Validation Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to a security bypass vulnerability because the
  application fails to properly validate the domain name in a signed CA certificate, allowing
  attackers to substitute malicious SSL certificates for trusted ones.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits allows attackers to perform
  man-in-the-middle attacks or impersonate trusted servers, which will aid in further attacks.");

  script_tag(name:"affected", value:"ProFTPD prior to 1.3.2b and 1.3.3 through 1.3.3.rc1.");

  script_tag(name:"solution", value:"Update to version 1.3.2b, 1.3.3rc2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36804");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3275");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.2b") ||
    version_in_range(version: version, test_version: "1.3.3", test_version2: "1.3.3rc1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.2b / 1.3.3rc2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
