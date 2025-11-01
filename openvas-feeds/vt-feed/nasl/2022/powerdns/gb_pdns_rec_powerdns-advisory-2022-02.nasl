# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148630");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2022-08-24 02:21:47 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 20:38:00 +0000 (Fri, 26 Aug 2022)");

  script_cve_id("CVE-2022-37428");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor DoS Vulnerability (2022-02)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_powerdns_dns_detect.nasl");
  script_mandatory_keys("powerdns/recursor/detected");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue only affects recursors which have protobuf logging
  enabled using the

  - protobufServer function with logResponses equals true or

  - outgoingProtobufServer function with logResponses equals true

  If either of these functions is used without specifying logResponses, its value is true. An
  attacker needs to have access to the recursor, i.e. the remote IP must be in the access control
  list. If an attacker queries a name that leads to an answer with specific properties, a protobuf
  message might be generated that causes an exception. The code does not handle this exception
  correctly, causing a denial of service.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.5.9 and prior, version 4.6.x
  through 4.6.2 and 4.7.x through 4.7.1.");

  script_tag(name:"solution", value:"Update to version 4.5.10, 4.6.3, 4.7.2 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2022-02.html");

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

if (version_is_less(version: version, test_version: "4.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.10");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6.0", test_version_up: "4.6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.3");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7.0", test_version_up: "4.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.2");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
