# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806051");
  script_version("2025-11-11T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-11 05:40:18 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"creation_date", value:"2015-09-14 17:59:32 +0530 (Mon, 14 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Monsta FTP Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Monsta FTP.");

  script_xref(name:"URL", value:"https://www.monstaftp.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/mftp", "/ftp", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";

  res = http_get_cache(port: port, item: url);

  if (('loginFormTitle">Monsta FTP' >< res && ">monsta" >< res) || 'ng-app="MonstaFTP"' >< res) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # var versionQS = "v=2.10.4
    vers = eregmatch(pattern: 'var versionQS\\s*=\\s*"v=([0-9.]+)', string: res);
    if (isnull(vers[1])) {
      # js/monsta-min-2.10.4.js
      vers = eregmatch(pattern: "monsta-min-([0-9.]+)\.js", string: res);
      if (isnull(vers[1]))
        # mftp-latest-version.php?v=2.1
        vers = eregmatch(pattern: "mftp-latest-version\.php\?v=([0-9.]+)", string: res);
        if (isnull(vers[1]))
          vers = eregmatch(pattern: "Monsta FTP v([0-9.]+)", string: res);
    }

    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "monsta_ftp/detected", value: TRUE);
    set_kb_item(name: "monsta_ftp/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:monstaftp:monsta_ftp:");
    if (!cpe)
      cpe = "cpe:/a:monstaftp:monsta_ftp";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Monsta FTP", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
