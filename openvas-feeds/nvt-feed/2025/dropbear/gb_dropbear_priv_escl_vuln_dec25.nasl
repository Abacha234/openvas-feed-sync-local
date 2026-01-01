# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124624");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-05-12 02:29:03 +0000 (Mon, 12 May 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2025-14282");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Dropbear 2024.84 - 2025.88 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Avoid privilege escalation via unix stream forwarding in
  Dropbear server. Other programs on a system may authenticate unix sockets via SO_PEERCRED, which
  would be root user for Dropbear forwarded connections, allowing root privilege escalation.");

  script_tag(name:"impact", value:"The flaw allows any authenticated user to run arbitrary programs
  as root (depending on other system programs).");

  script_tag(name:"affected", value:"Dropbear version 2024.84 through 2025.88.");

  script_tag(name:"solution", value:"Update to version 2025.89 or later.");

  script_xref(name:"URL", value:"https://lists.ucc.gu.uwa.edu.au/pipermail/dropbear/2025q4/002390.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/16/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/16/4");
  script_xref(name:"URL", value:"https://github.com/turistu/odds-n-ends/blob/main/CVE-2025-14282.md");
  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/CHANGES");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2024.84", test_version2: "2025.88")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2025.89", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
