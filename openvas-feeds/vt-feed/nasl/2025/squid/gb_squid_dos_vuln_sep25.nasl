# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155471");
  script_version("2025-10-01T05:39:08+0000");
  script_tag(name:"last_modification", value:"2025-10-01 05:39:08 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-09-30 03:35:08 +0000 (Tue, 30 Sep 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2025-59362");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Squid Buffer Overflow Vulnerability (Sep 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a buffer overflow vulnerability as it
  mishandles ASN.1 encoding of long SNMP OIDs.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow vulnerability exists in the SNMP
  (Simple Network Management Protocol) message processing component of Squid Cache. The flaw is
  present in the asn_build_objid function located in the lib/snmplib/asn1.c library, which is
  responsible for encoding Object Identifiers (OIDs) into the ASN.1 BER format for SNMP
  responses.");

  script_tag(name:"affected", value:"Squid version 7.1 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 30th September, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Microsvuln/advisories/blob/main/CVE-2025-59362/CVE-2025-59362.md");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/pull/2149");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
