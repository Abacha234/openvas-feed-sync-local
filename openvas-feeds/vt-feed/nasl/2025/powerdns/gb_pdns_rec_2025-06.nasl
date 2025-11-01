# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119216");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-30 09:17:28 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:P");

  script_cve_id("CVE-2025-59023", "CVE-2025-59024");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor Multiple Cache Pollution Vulnerabilities (2025-06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powerdns_dns_detect.nasl");
  script_mandatory_keys("powerdns/recursor/detected");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to multiple cache pollution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-59023: A cache pollution vulnerability which can be triggered by an attacker spoofing
  crafted delegations

  - CVE-2025-59024: A cache pollution vulnerability which can be triggered by an attacker using an
  UDP IP fragments attack");

  script_tag(name:"affected", value:"PowerDNS Recursor version 5.1.7 and prior, 5.2.x through
  5.2.5 and 5.3.0 only.");

  script_tag(name:"solution", value:"Update to version 5.1.8, 5.2.6, 5.3.1 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2025-06.html");
  script_xref(name:"URL", value:"https://blog.powerdns.com/powerdns-security-advisory-2025-06-2025-10-22");

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

if (version_is_less_equal(version: version, test_version: "5.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.8");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
