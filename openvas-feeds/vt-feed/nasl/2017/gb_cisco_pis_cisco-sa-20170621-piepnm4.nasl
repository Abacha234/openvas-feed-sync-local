# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106900");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-06-22 13:24:18 +0700 (Thu, 22 Jun 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-07 17:03:00 +0000 (Fri, 07 Jul 2017)");

  script_cve_id("CVE-2017-6700");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Prime Infrastructure DOM Cross-Site Scripting Vulnerability (cisco-sa-20170621-piepnm4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_pis_consolidation.nasl");
  script_mandatory_keys("cisco/pis/detected");

  script_tag(name:"summary", value:"A vulnerability in the web-based management interface of Cisco
  Prime Infrastructure (PI) could allow an unauthenticated, remote attacker to conduct a Document
  Object Model (DOM) based (environment or client-side) cross-site scripting (XSS) attack against a
  user of the web-based management interface of an affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of
  user-supplied input by the web-based management interface of an affected device. An attacker
  could exploit this vulnerability by persuading a user of the interface to click a crafted
  link.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute
  arbitrary script code in the context of the interface or allow the attacker to access sensitive
  browser-based information.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-piepnm4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version == "3.1.1") {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
