# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119134");
  script_version("2025-10-08T05:38:55+0000");
  script_tag(name:"last_modification", value:"2025-10-08 05:38:55 +0000 (Wed, 08 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-07 08:43:45 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-61984", "CVE-2025-61985");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH < 10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-61984: 'ssh' allows control characters in usernames that originate from certain
  possibly untrusted sources, potentially leading to code execution when a ProxyCommand is used. The
  untrusted sources are the command line and %-sequence expansion of a configuration file. (A
  configuration file that provides a complete literal username is not categorized as an untrusted
  source.)

  - CVE-2025-61985: 'ssh' allows the '\0' character in an ssh:// URI, potentially leading to code
  execution when a ProxyCommand is used.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH versions prior to 10.1.");

  script_tag(name:"solution", value:"Update to version 10.1 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-10.1");
  script_xref(name:"URL", value:"https://www.openssh.com/security.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/06/1");
  script_xref(name:"URL", value:"https://dgl.cx/2025/10/bash-a-newline-ssh-proxycommand-cve-2025-61984#_");

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

if (version_is_less(version: version, test_version: "10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
