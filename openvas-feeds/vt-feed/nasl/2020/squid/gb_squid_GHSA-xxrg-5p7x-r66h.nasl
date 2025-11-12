# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143623");
  script_version("2025-11-11T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-11 05:40:18 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"creation_date", value:"2020-03-23 04:00:09 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-22 15:15:00 +0000 (Wed, 22 Jul 2020)");

  script_cve_id("CVE-2019-18860");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid < 7.0.1 XSS Vulnerability (SQUID-2023:6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a cross-site scripting (XSS) vulnerability in
  cachemgr.cgi.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Squid, when certain web browsers are used, mishandles HTML
  in the host (aka hostname) parameter to cachemgr.cgi.

  Note: This flaw had received an incomplete fix in version 4.9 back in 2019.");

  script_tag(name:"affected", value:"Squid versions prior to version 7.0.1.");

  script_tag(name:"solution", value:"Update to version 7.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-xxrg-5p7x-r66h");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/11/04/7");
  # nb: This one has a description on the incomplete fix done in version 4.9 back then in 2019:
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/11/05/7");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/pull/2294");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/pull/505");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/pull/505");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/pull/504");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
