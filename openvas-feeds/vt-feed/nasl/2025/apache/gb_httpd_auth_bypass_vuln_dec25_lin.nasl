# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125567");
  script_version("2025-12-05T05:44:55+0000");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-04 14:00:00 +0000 (Thu, 04 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-66200");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.7 - 2.4.65 Authentication Bypass Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"mod_userdir+suexec bypass via AllowOverride FileInfo
  vulnerability in Apache HTTP Server. Users with access to use the RequestHeader directive in
  htaccess can cause some CGI scripts to run under an unexpected userid.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.7 through 2.4.65.");

  script_tag(name:"solution", value:"Update to version 2.4.66 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.66");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/04/8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.4.7", test_version2: "2.4.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.66", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
