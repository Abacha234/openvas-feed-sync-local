# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125401");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-28 08:24:34 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2025-55754");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Console Manipulation Vulnerability (Oct 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a console manipulation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tomcat does not escape ANSI escape sequences in log messages.
  When Tomcat runs in a Windows console that supports ANSI sequences, an attacker can use a
  specially crafted URL to inject ANSI escape codes that manipulate the console and the clipboard
  and try to trick an administrator into executing an attacker-controlled command. No practical
  attack vector has been found, but a similar attack could be possible on other operating
  systems.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.40 through 9.0.108, 10.1.0-M1
  through 10.1.44 and 11.0.0-M1 through 11.0.10.

  Vendor notes:

  - While no attack vector was found, it may have been possible to mount this attack on other
  operating systems besides Windows

  - Older, EOL versions may also be affected");

  script_tag(name:"solution", value:"Update to version 9.0.109, 10.1.45, 11.0.11 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/j7w54hqbkfcn0xb9xy0wnx8w5nymcbqd");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.11");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.45");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.109");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/27/5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.0.40", test_version2: "9.0.108")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.109", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.M1", test_version2: "10.1.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.45", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0.M1", test_version2: "11.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
