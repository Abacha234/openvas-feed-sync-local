# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155713");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-06 08:58:56 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("motionEye Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8765);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of motionEye.");

  script_xref(name:"URL", value:"https://github.com/motioneye-project/motioneye/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8765);

url = "/";

res = http_get_cache(port: port, item: url);

if (">motionEye<" >< res && 'class="modal-glass">' >< res) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "motioneye/detected", value: TRUE);
  set_kb_item(name: "motioneye/http/detected", value: TRUE);

  # Server: motionEye/0.42.1
  vers = eregmatch(pattern: "[Ss]erver\s*:\s*motionEye/([0-9.]+)", string: res, icase: FALSE);
  if (!isnull(vers[1])) {
    version = vers[1];
  } else {
    # favicon.ico?v=0.42.1
    # manifest.json?v=0.42.1
    # jquery.min.js?v=0.42.1
    vers = eregmatch(pattern: "\.(ico|json|js)\?v=([0-9]+\.[0-9.]+)", string: res);
    if (!isnull(vers[2]))
      version = vers[2];
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:motioneye_project:motioneye:");
  if (!cpe)
    cpe = "cpe:/a:motioneye_project:motioneye";

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "motionEye Detection (HTTP)");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "motionEye", version: version, install: location, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
