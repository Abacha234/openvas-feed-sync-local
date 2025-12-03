# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125543");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-11-27 14:02:14 +0000 (Thu, 27 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology BeeStation / Synology BeeStation OS (BSM) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Synology BeeStation and the underlying
  BeeStation OS (BSM).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6600);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://bee.synology.com/en-global/BeeStation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 6600);

url = "/";
concluded = "";
found = FALSE;

res = http_get_cache(port: port, item: url);

# Examples:
# <title>BeeStation&nbsp;-&nbsp;Synology&nbsp;BeeStation</title>
# <meta name="application-name" content="BeeStation&nbsp;-&nbsp;Synology&nbsp;BeeStation" />
# script type="text/javascript" src="webman/3rdparty/bee-AdminCenter/preload.js?v=1761883910"></script>
# <script ... &launchApp=SYNO.SDS.Bee.Instance& ...
if (res =~ "^HTTP/1\.[01] 200" && (("Synology" >< res &&
     ("<title>BeeStation" >< res || 'content="BeeStation' >< res )) ||
     ("bee-AdminCenter" >< res && "SYNO.SDS.Bee.Instance" >< res))) {

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  concl = eregmatch(pattern: '[^\r\n]*(<title>BeeStation|content="BeeStation|bee-AdminCenter)[^\r\n]*', string: res);
  if (!isnull(concl[0]))
    concluded = concl[0];

  found = TRUE;
}

if (!found) {
  # BeeStation with cloud login configuration / fallback
  url = "/webapi/entry.cgi?api=SYNO.Core.Desktop.SessionData&version=1&method=getjs";
  res = http_get_cache(port: port, item: url);

  # Examples:
  # "appIconPath" : "webman/3rdparty/bee-AdminCenter/images/icon/bee_icon_60.png",
  # "bsm_login_enabled" : true,
  if (res =~ "^HTTP/1\.[01] 200" &&
     ("bee-AdminCenter" >< res && res =~ '"bsm_login_enabled"\\s*:\\s*true')) {

    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    concl = eregmatch(pattern: '[^\r\n]*(bee-AdminCenter|bsm_login_enabled)[^\r\n]*', string: res);
    if (!isnull(concl[0]))
      concluded = concl[0];

    found = TRUE;
  }
}

if (found == TRUE) {

  version = "unknown";
  location = "/";

  os_name = "Synology BeeStation OS (BSM)";
  hw_name = "Synology BeeStation";

  set_kb_item(name: "synology/beestation/detected", value: TRUE);
  set_kb_item(name: "synology/beestation/http/detected", value: TRUE);

  os_cpe = "cpe:/o:synology:beestation_os";
  hw_cpe = "cpe:/o:synology:beestation";

  os_register_and_report(os: os_name, cpe: os_cpe, port: port, runs_key: "unixoide",
                         desc: "Synology BeeStation OS (BSM) Detection (HTTP)");

  register_product(cpe: os_cpe, location: location, port: port, service: "www");
  register_product(cpe: hw_cpe, location: location, port: port, service: "www");


  report = build_detection_report(app: os_name, version: version,
                                  concluded: concluded, install: location, cpe: os_cpe,
                                  concludedUrl: conclUrl);
  report += '\n\n';

  report += build_detection_report(app: hw_name, skip_version: TRUE,
                                   install: location, cpe: hw_cpe);

  log_message(port: port, data: report);
}

exit(0);
