# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133153");
  script_version("2026-01-08T05:48:01+0000");
  script_tag(name:"last_modification", value:"2026-01-08 05:48:01 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"creation_date", value:"2025-12-23 08:29:03 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-19 18:09:20 +0000 (Tue, 19 Feb 2019)");

  script_cve_id("CVE-2019-6111");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Dropbear < 2025.89 SCP Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is prone to an scp directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When copying files from a remote system to a local directory,
  scp(1) does not verify that the filenames that the server sent matched those requested by the
  client.");

  script_tag(name:"impact", value:"This could allow a hostile server to create or clobber unexpected
  local files with attacker-controlled content.");

  script_tag(name:"affected", value:"Dropbear scp function prior to version 2025.89.");

  script_tag(name:"solution", value:"Update to version 2025.89 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/16/2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/362POC6TTSXVH3GN2FECATQBAMCINKKJ/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/04/18/1");

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

if (version_is_less(version: version, test_version: "2025.89")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2025.89", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
