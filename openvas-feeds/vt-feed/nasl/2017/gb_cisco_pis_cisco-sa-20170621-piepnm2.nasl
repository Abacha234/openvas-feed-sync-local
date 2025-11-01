# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106898");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-06-22 13:24:18 +0700 (Thu, 22 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-07 16:56:00 +0000 (Fri, 07 Jul 2017)");

  script_cve_id("CVE-2017-6698");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Prime Infrastructure SQL Injection Vulnerability (cisco-sa-20170621-piepnm2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_pis_consolidation.nasl");
  script_mandatory_keys("cisco/pis/detected");

  script_tag(name:"summary", value:"A vulnerability in the Cisco Prime Infrastructure (PI) SQL
  database interface could allow an authenticated, remote attacker to impact the confidentiality
  and integrity of the application by executing arbitrary SQL queries.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper validation on
  user-supplied input within SQL queries. An attacker could exploit this vulnerability by sending
  crafted URLs that contain malicious SQL statements to the affected application.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to determine the presence of
  certain values and write malicious input to the SQL database.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-piepnm2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version == "3.1.1") {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
