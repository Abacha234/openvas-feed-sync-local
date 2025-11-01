# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143205");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-11-29 03:21:30 +0000 (Fri, 29 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-11 16:16:00 +0000 (Wed, 11 Dec 2019)");

  script_cve_id("CVE-2019-19271", "CVE-2019-19272");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD < 1.3.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to multiple vulnerabilities in the handling of
  CRLs in mod_tls.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ProFTPD prior to version 1.3.6.");

  script_tag(name:"solution", value:"Update to version 1.3.6 or later.");

  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/860");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/858");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
