# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:log4j";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156064");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-19 04:00:06 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-68161");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Log4j 2.x < 2.25.3 Missing TLS Hostname Verification Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_log4j_consolidation.nasl");
  script_mandatory_keys("apache/log4j/ssh-login/detected");

  script_tag(name:"summary", value:"Apache Log4j is prone to a missing TLS hostname verification
  vulnerability in the socket appender.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Socket Appender does not perform TLS hostname verification
  of the peer certificate, even when the verifyHostName configuration attribute or the
  log4j2.sslVerifyHostName system property is set to true.");

  script_tag(name:"impact", value:"This issue may allow a man-in-the-middle attacker to intercept
  or redirect log traffic under the following conditions:

  - The attacker is able to intercept or redirect network traffic between the client and the log
  receiver.

  - The attacker can present a server certificate issued by a certification authority trusted by
  the Socket Appender's configured trust store (or by the default Java trust store if no custom
  trust store is configured).");

  script_tag(name:"affected", value:"Apache Log4j versions 2.0-beta9 through 2.25.2.");

  script_tag(name:"solution", value:"Update to version 2.25.3 or later.");

  script_xref(name:"URL", value:"https://logging.apache.org/security.html#CVE-2025-68161");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/18/1");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.25.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.25.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
