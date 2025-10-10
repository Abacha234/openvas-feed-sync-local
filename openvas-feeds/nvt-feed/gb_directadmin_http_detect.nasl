# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106500");
  script_version("2025-10-09T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-10-09 05:39:13 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-01-09 10:12:05 +0700 (Mon, 09 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DirectAdmin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2222);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DirectAdmin.");

  script_add_preference(name:"DirectAdmin Web UI Username (Admin User)", value:"", type:"entry", id:1);
  script_add_preference(name:"DirectAdmin Web UI Password (Admin User)", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.directadmin.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 2222);

url = "/";

res = http_get_cache(port: port, item: url);

if ("<title>DirectAdmin Login</title>" >!< res && "Server: DirectAdmin Daemon" >!< res) {
  url = "/evo/login";

  res = http_get_cache(port: port, item: url);

  if ("DirectAdmin</title>" >!< res || 'id="portal-targets"' >!< res)
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

# DirectAdmin Daemon v1.61.3
vers = eregmatch(pattern: "DirectAdmin Daemon v([0-9.]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
} else {
  user = script_get_preference("DirectAdmin Web UI Username (Admin User)", id: 1);
  pass = script_get_preference("DirectAdmin Web UI Password (Admin User)", id: 2);

  if (!user && !pass) {
    extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
  } else if (!user && pass) {
    extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
  } else if (user && !pass) {
    extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
  } else if (user && pass) {
    url = "/api/version";

    headers = make_array("Authorization", "Basic " + base64(str: user + ":" + pass));

    req = http_get_req(port: port, url: url, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);

    if (res =~ "^HTTP/1\.[01] 200" && '"version"' >< res) {
      # {"commit":"a87d1f2260680458e0ac27b6774851b1cbaa9d80","version":"1.687","arch":"amd64","os":"linux","distro":"rhel8","eol":false,"uptime":7763829200293,"update":{"available":false,"availableChannels":["current","stable","alpha"],"channel":"alpha","commit":"a87d1f2260680458e0ac27b6774851b1cbaa9d80","version":"1.687"},"buildDistro":"linux_amd64","detectedDistro":"rhel8_amd64"}
      vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)"', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    } else {
      extra += "  Note: Username and password were provided but authentication failed.";
    }
  }
}

set_kb_item(name: "directadmin/detected", value: TRUE);
set_kb_item(name: "directadmin/http/detected", value: TRUE);

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                       desc: "DirectAdmin Detection (HTTP)");

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:directadmin:directadmin:");
if (!cpe)
  cpe = "cpe:/a:directadmin:directadmin";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "DirectAdmin", version: version, install: location,
                                         cpe: cpe, concluded: vers[0], concludedUrl: conclUrl,
                                         extra: extra),
            port: port);
exit(0);
