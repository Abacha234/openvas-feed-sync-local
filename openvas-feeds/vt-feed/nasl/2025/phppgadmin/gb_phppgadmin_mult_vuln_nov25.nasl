# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phppgadmin:phppgadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133119");
  script_version("2025-11-25T05:40:35+0000");
  script_tag(name:"last_modification", value:"2025-11-25 05:40:35 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-21 11:57:02 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2025-60796", "CVE-2025-60797", "CVE-2025-60798", "CVE-2025-60799");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("phpPgAdmin <= 7.13.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phppgadmin_http_detect.nasl");
  script_mandatory_keys("phppgadmin/detected");

  script_tag(name:"summary", value:"phpPgAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-60796: Contains multiple cross-site scripting (XSS) vulnerabilities across various
  components. User-supplied inputs from $_REQUEST parameters are reflected in HTML output without
  proper encoding or sanitization in multiple locations including sequences.php, indexes.php,
  admin.php, and other unspecified files. An attacker can exploit these vulnerabilities to execute
  arbitrary JavaScript in victims browsers, potentially leading to session hijacking, credential
  theft, or other malicious actions.

  - CVE-2025-60797: Contains a SQL injection vulnerability in dataexport.php. The application
  directly executes user-supplied SQL queries from the $_REQUEST['query'] parameter without any
  sanitization or parameterization via $data->conn->Execute($_REQUEST['query']). An authenticated
  attacker can exploit this vulnerability to execute arbitrary SQL commands, potentially leading to
  complete database compromise, data theft, or privilege escalation.

  - CVE-2025-60798: Contains a SQL injection vulnerability in display.php. The application passes
  user-controlled input from $_REQUEST['query'] directly to the browseQuery function without proper
  sanitization. An authenticated attacker can exploit this vulnerability to execute arbitrary SQL
  commands through malicious query manipulation, potentially leading to complete database
  compromise.

  - CVE-2025-60799: Contains an incorrect access control vulnerability in sql.php. The application
  allows unauthorized manipulation of session variables by accepting user-controlled parameters
  ('subject', 'server', 'database', 'queryid') without proper validation or access control checks.
  Attackers can exploit this to store arbitrary SQL queries in $_SESSION['sqlquery'] by manipulating
  these parameters, potentially leading to session poisoning, stored cross-site scripting, or
  unauthorized access to sensitive session data.");

  script_tag(name:"affected", value:"phpPgAdmin version 7.13.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 21st November, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-h369-cpjj-qfff");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-927w-vq5c-8gc3");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-g6xh-wrpf-v6j6");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-r63p-v37q-g74c");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7.13.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
