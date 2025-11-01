# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807394");
  script_version("2025-10-31T05:40:56+0000");
  script_cve_id("CVE-2014-3614");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-01-17 14:50:29 +0530 (Tue, 17 Jan 2017)");
  script_name("PowerDNS Recursor 3.6.0 Specific Sequence DoS Vulnerability (2014-01)");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  handling a specific sequence of packets which leads to  crash PowerDNS
  Recursor remotely.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 3.6.0 only.");

  script_tag(name:"solution", value:"Update to version 3.6.1 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2014-01.html");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q3/589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69778");
  script_xref(name:"URL", value:"https://blog.powerdns.com/2014/09/10/security-update-powerdns-recursor-3-6-1");
  script_xref(name:"URL", value:"http://doc.powerdns.com/html/changelog.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_powerdns_dns_detect.nasl");
  script_mandatory_keys("powerdns/recursor/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe:CPE, port:port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if(version_is_equal(version: version, test_version: "3.6.0")) {
  fix = "3.6.1";
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);
