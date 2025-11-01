# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113391");
  script_version("2025-10-09T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-10-09 05:39:13 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"creation_date", value:"2019-05-16 10:16:17 +0200 (Thu, 16 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron AirMedia Presentation Gateway Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Crestron AirMedia Presentation Gateway
  devices.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/cgi-bin/login.cgi?lang=en&src=AwLoginDownload.html";

buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && "<title>Crestron AirMedia</title>" >< buf ) {
  detected = TRUE;
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
}

if( ! detected ) {
  url = "/index_airmedia.html";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && "<title>Crestron AirMedia</title>" >< buf && "Crestron Webserver" >< buf ) {
    detected = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( detected ) {
  set_kb_item( name:"crestron_airmedia/detected", value:TRUE );
  set_kb_item( name:"crestron_airmedia/http/detected", value:TRUE );
  set_kb_item( name:"crestron_airmedia/http/port", value:port );
  set_kb_item( name:"crestron_airmedia/http/" + port + "/concludedUrl", value:conclUrl );
}

exit( 0 );
