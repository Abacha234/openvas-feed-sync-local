# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105615");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2016-04-21 11:49:04 +0200 (Thu, 21 Apr 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-29 17:47:00 +0000 (Mon, 29 Jul 2019)");

  script_cve_id("CVE-2016-1291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Prime Infrastructure Remote Code Execution Vulnerability (cisco-sa-20160406-remcode) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_pis_consolidation.nasl");
  script_mandatory_keys("cisco/pis/detected");

  script_tag(name:"summary", value:"A vulnerability in the web interface of Cisco Prime
  Infrastructure could allow an unauthenticated, remote attacker to execute arbitrary code on a
  targeted system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of HTTP
  user-supplied input. An attacker could exploit this vulnerability by sending an HTTP POST with
  crafted deserialized user data.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary code
  with root-level privileges on the affected system, which could be used to conduct further
  attacks.");

  script_tag(name:"affected", value:"Cisco Prime Infrastructure prior to version 2.2.3 Update 4 and
  3.0 prior to 3.0.2.");

  script_tag(name:"solution", value:"Update to version 2.2.3 Update 4, 3.0.2 or later.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-remcode");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2.2.3"))
  fix = "2.2.3 Update 4";

if (version =~ "^2\.2\.3") {
  installed_patches = get_kb_item("cisco/pis/installed_patches");
  if (!installed_patches || "Update 4" >!< installed_patches)
    fix = "2.2.3 Update 4";
}

if (version =~ "^3\.")
  if (version_is_less(version: version, test_version: "3.0.2"))
    fix = "3.0.2";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
