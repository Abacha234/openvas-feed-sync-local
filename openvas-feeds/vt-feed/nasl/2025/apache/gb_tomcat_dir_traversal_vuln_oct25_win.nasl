# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125400");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-28 08:24:34 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-55752");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Directory Traversal Vulnerability (Oct 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The fix for bug 60013 introduced a regression where the
  rewritten URL was normalized before it was decoded. This introduced the possibility that, for
  rewrite rules that rewrite query parameters to the URL, an attacker could manipulate the request
  URI to bypass security constraints including the protection for /WEB-INF/ and /META-INF/. If PUT
  requests were also enabled then malicious files could be uploaded leading to remote code
  execution. PUT requests are normally limited to trusted users and it is considered unlikely that
  PUT requests would be enabled in conjunction with a rewrite that manipulated the URI.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M11 through 9.0.108, 10.1.0-M1
  through 10.1.44 and 11.0.0-M1 through 11.0.10.

  Vendor note: Older, EOL versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 9.0.109, 10.1.45, 11.0.11 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/n05kjcwyj1s45ovs8ll1qrrojhfb1tog");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.11");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.45");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.109");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/27/4");

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

if (version_in_range(version: version, test_version: "9.0.0.M11", test_version2: "9.0.108")) {
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
