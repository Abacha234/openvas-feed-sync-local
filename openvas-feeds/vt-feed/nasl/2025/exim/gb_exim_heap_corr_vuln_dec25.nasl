# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156038");
  script_version("2025-12-24T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-24 05:46:55 +0000 (Wed, 24 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-15 09:23:09 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-22 19:15:45 +0000 (Mon, 22 Dec 2025)");

  script_cve_id("CVE-2025-67896");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.99 Heap Corruption Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a heap corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In vulnerable configurations, a remote, unauthenticated
  attacker can achieve heap corruption.");

  script_tag(name:"affected", value:"Exim version 4.99. Other versions prior to 4.98.1 (which is
  mentioned by the vendor as the only unaffected older version) might be affected as well.");

  script_tag(name:"solution", value:"Update to version 4.99.1 or later.");

  script_xref(name:"URL", value:"https://code.exim.org/exim/exim/src/branch/exim-4.99+fixes/doc/doc-txt/exim-security-2025-12-09.1/report.txt");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/10/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/11/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/14/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/18/3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.98.1") ||
    version_is_equal(version: version, test_version: "4.99")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.99.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
