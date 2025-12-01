# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lynxtechnology:twonky_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155825");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-20 05:40:19 +0000 (Thu, 20 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-13315");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Twonky Server <= 8.5.2 Authentication Bypass Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_http_detect.nasl");
  script_mandatory_keys("twonky/server/http/detected");
  script_require_ports("Services/www", 9000);

  script_tag(name:"summary", value:"Twonky Server is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"An unauthenticated remote attacker can bypass web service API
  authentication controls to leak a log file and read the administrator's username and encrypted
  password.");

  script_tag(name:"affected", value:"Twonky Server version 8.5.2 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 20th November, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.rapid7.com/blog/post/cve-2025-13315-cve-2025-13316-critical-twonky-server-authentication-bypass-not-fixed/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/nmc/rpc/log_getfile";

if (http_vuln_check(port: port, url: url, pattern: "LOG_SYSTEM", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
