# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141899");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2019-01-22 09:19:38 +0700 (Tue, 22 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:49:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2019-3807");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor 4.1.x < 4.1.9 DNSSEC Signature Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powerdns_dns_detect.nasl");
  script_mandatory_keys("powerdns/recursor/detected");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS Recursor where records in the answer
section of responses received from authoritative servers with the AA flag not set were not properly validated,
allowing an attacker to bypass DNSSEC validation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Recursor versions 4.1.x through 4.1.8.");

  script_tag(name:"solution", value:"Update to version 4.1.9 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2019-02.html");

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

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.9");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
