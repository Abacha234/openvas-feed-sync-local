# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143939");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2020-05-20 02:25:35 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-14 19:15:00 +0000 (Sun, 14 Jun 2020)");

  script_cve_id("CVE-2020-10030", "CVE-2020-10995", "CVE-2020-12244");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor 4.1.0 < 4.1.16, 4.2.0 < 4.2.2, 4.3.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powerdns_dns_detect.nasl");
  script_mandatory_keys("powerdns/recursor/detected");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PowerDNS Recursor is prone to multiple vulnerabilities:

  - Information disclosure vulnerability (CVE-2020-10030)

  - DoS vulnerability (CVE-2020-10995)

  - Insufficient validation of DNSSEC signatures (CVE-2020-12244)");

  script_tag(name:"affected", value:"PowerDNS Recursor versions 4.1.0 through 4.1.15, 4.2.0 through
  4.2.1 and 4.3.0 only.");

  script_tag(name:"solution", value:"Update to version 4.1.16, 4.2.2, 4.3.1 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2020-01.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2020-02.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2020-03.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.16");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.2");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version == "4.3.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
