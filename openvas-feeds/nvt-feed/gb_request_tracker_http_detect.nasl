# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100385");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2009-12-09 13:16:50 +0100 (Wed, 09 Dec 2009)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Request Tracker (RT) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Request Tracker (RT).");

  script_xref(name:"URL", value:"https://requesttracker.com/request-tracker/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/rt", "/tracker", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.html";

  res = http_get_cache(port: port, item: url);

  if (egrep(pattern: "&#187;&#124;&#171; RT.*Best Practical Solutions, LLC", string: res, icase: TRUE) ||
      (">Request Tracker<" >< res && "rt-header-container" >< res) || "RT.CurrentUser" >< res) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # <p id="bpscredits"><span>&#187;&#124;&#171; RT 4.4.3 Copyright 1996-2018 <a href="http://www.bestpractical.com?rt=4.4.3">Best Practical Solutions, LLC</a>.
    vers = eregmatch(pattern: "&#187;&#124;&#171;\s+RT\s+([0-9.]+)(rc[0-9]+)?", string: res, icase: TRUE);

    if (!isnull(vers[1]) && !isnull(vers[2])) {
      version = vers[1] + "." + vers[2];
    } else if (!isnull(vers[1]) && isnull(vers[2])) {
      version = vers[1];
    }

    if (version == "unknown") {
      url = dir + "/REST/1.0/";

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      # RT/5.0.3 401 Credentials required
      vers = eregmatch(pattern: "^RT/([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "request_tracker/detected", value: TRUE);
    set_kb_item(name: "request_tracker/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9rc.]+)", base: "cpe:/a:bestpractical:request_tracker:");
    if (!cpe)
      cpe = "cpe:/a:bestpractical:request_tracker";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Request Tracker (RT)", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
