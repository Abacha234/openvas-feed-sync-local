# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133095");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-27 07:26:10 +0000 (Mon, 27 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2025-11411");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver < 1.24.1 Domain Hijacking Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_unbound_dns_detect.nasl");
  script_mandatory_keys("unbound/detected");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a domain hijacking
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Promiscuous NS RRSets that complement positive DNS replies in
  the authority section can be used to trick resolvers to update their delegation information for
  the zone. Usually these RRSets are used to update the resolver's knowledge of the zone's name
  servers. A malicious actor can exploit the possible poisonous effect by injecting NS RRSets (and
  possibly their respective address records) in a reply. This could be done for example by trying
  to spoof a packet or fragmentation attacks. Unbound would then proceed to update the NS RRSet
  data it already has since the new data has enough trust for it, i.e., in-zone data for the
  delegation point.");

  script_tag(name:"affected", value:"Unbound DNS Resolver versions prior to 1.24.1.");

  script_tag(name:"solution", value:"Update to version 1.24.1 or later.");

  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/news/2025/Oct/22/unbound-1.24.1-released/");
  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/unbound/CVE-2025-11411.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "1.24.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.24.1");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
