# SPDX-FileCopyrightText: 2006 David Maciejak
# SPDX-FileCopyrightText: Improved / extended code / detection routine since 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20377");
  script_version("2025-10-31T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-10-31 15:42:05 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Windows Server Update Services (WSUS) Administration Console Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 8530, 8531);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Microsoft Windows Server Update
  Services (WSUS) via an exposed administration console.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

ports = http_get_ports( default_port_list:make_list( 8530, 8531 ) );

foreach port( ports ) {

  # nb: Even if there is no web page this shouldn't be a big problem as the Microsoft Server/Service
  # should be detected via the banner accordingly.
  if( ! http_can_host_asp( port:port ) )
    continue;

  url = "/WsusAdmin/Errors/BrowserSettings.aspx";
  res = http_get_cache( port:port, item:url );
  if( ! res || res =~ "^HTTP/1\.[01] 40[34]" )
    continue;

  found = FALSE;
  concluded = "";

  # nb: This was initially a single pattern in "egrep" like this:
  # <title>Windows Server Update Services error</title>.*href="/WsusAdmin/Common/Common.css"
  # but has been split later for better matching / easier concluded reporting.
  if( ( concl = egrep( pattern:"<title>Windows Server Update Services error</title>", string:res, icase:FALSE ) ) &&
      'href="/WsusAdmin/Common/Common.css"' >< res ) {
    concluded = "    " + chomp( concl );
    found = TRUE;
  }

  if( concl = egrep( pattern:'<div class="CurrentNavigation">Windows Server Update Services error</div>', string:res ) ) {
    if( concluded )
      concluded += '\n';
    concluded += "    " + chomp( concl );
    found = TRUE;
  }

  if( found ) {

    version = "unknown";
    conclurl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"microsoft/wsus/detected", value:TRUE );
    set_kb_item( name:"microsoft/wsus/http/detected", value:TRUE );
    set_kb_item( name:"microsoft/wsus/http-admin/detected", value:TRUE );
    set_kb_item( name:"microsoft/wsus/http-admin/" + port + "/detected", value:TRUE );
    set_kb_item( name:"microsoft/wsus/http-admin/port", value:port );
    set_kb_item( name:"microsoft/wsus/http-admin/" + port + "/concluded", value:concluded );
    set_kb_item( name:"microsoft/wsus/http-admin/" + port + "/concludedUrl", value:conclurl );
    set_kb_item( name:"microsoft/wsus/http-admin/" + port + "/detected", value:TRUE );
    set_kb_item( name:"microsoft/wsus/http-admin/" + port + "/version", value:version );

    # nb: For reporting in gsf/2025/microsoft/gb_wsus_wan_access.nasl
    set_kb_item( name:"microsoft/wsus/http/" + port + "/accessible_endpoints", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }
}

exit( 0 );
