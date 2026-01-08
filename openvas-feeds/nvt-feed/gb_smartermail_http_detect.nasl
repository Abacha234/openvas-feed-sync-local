# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902258");
  script_version("2026-01-07T05:47:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2026-01-07 05:47:44 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SmarterTools SmarterMail Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_microsoft_iis_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SmarterTools SmarterMail.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9998);

if (!http_can_host_asp(port: port))
  exit(0);

url = "/Login.aspx";

res = http_get_cache(port: port, item: url);

if (">SmarterMail" >!< res && ">SmarterMail Enterprise" >!< res && ">SmarterMail Standard" >!< res) {
  url = "/interface/root";

  res = http_get_cache(port: port, item: url);

  if ('ng-app="smartermail"' >!< res && "var stSystemHostname" >!< res)
    exit(0);
}

version = "unknown";
install = "/";
conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "smartertools/smartermail/detected", value: TRUE);
set_kb_item(name: "smartertools/smartermail/http/detected", value: TRUE);
set_kb_item(name: "smartertools/smartermail/http/port", value: port);

# >SmarterMail Enterprise 15.7<
vers = eregmatch(pattern:">SmarterMail [a-zA-Z]+ ([0-9.]+)<", string: res);
if (isnull(vers[1])) {
  # var stProductVersion = "100.0.9483";
  vers = eregmatch(pattern: 'stProductVersion\\s*=\\s*"([0-9.]+)"', string: res);
}

if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "smartertools/smartermail/http/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "smartertools/smartermail/http/" + port + "/version", value: version);
set_kb_item(name: "smartertools/smartermail/http/" + port + "/concludedUrl", value: conclUrl);

exit(0);
