# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108003");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"creation_date", value:"2016-09-27 12:00:00 +0200 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Twonky Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Twonky Server.");

  script_xref(name:"URL", value:"https://lynxtechnology.com/twonky-server.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:9000 );

host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  if( dir == "/webconfig" )
    continue; # nb: Avoids doubled detection at / and /webconfig if GUI is password protected

  url = dir + "/";

  res = http_get_cache( port:port, item:url );

  if( "<title>Twonky Server</title>" >< res ||
      '<div id="twFooter">' >< res ||
      "<title>TwonkyServer Media Browser</title>" >< res ||
      # 2004-2011 PacketVideo Corporation. All rights reserved.</div>
      # 2004-2009 PacketVideo&nbsp;Corporation. All&nbsp;rights&nbsp;reserved</div>
      res =~ "PacketVideo(\s|&nbsp;)Corporation\.(\s|&nbsp;)All(\s|&nbsp;)rights(\s|&nbsp;)reserved" ||
      "<title>TwonkyMedia</title>" >< res ||
      "<title>TwonkyServer</title>" >< res ||
      "<title>Twonky</title>" >< res ||
      '<script type="text/javascript" src="http://profile.twonky.com/tsconfig/js/onlinesvcs.js" defer="defer"></script>' >< res ||
      ( '<li><a href="https://twitter.com/Twonky" id="twSoctw"' >< res && '<li><a href="http://www.facebook.com/Twonky" id="twSocfb"' >< res ) ) {

    version = "unknown";
    concludedUrl = "  " + http_report_vuln_url( port:port, url:url, url_only: TRUE );
    extra   = "";

    url = dir + "/rpc/info_status";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    # version|8.2
    # version|7.2.9-6
    # version|7.2.9-13
    # version|7.1.1-dsd
    vers = eregmatch( pattern:"version\|([0-9.]+(-[0-9]+)?)", string:res );
    if( res =~ "^HTTP/1\.[01] 200" && vers[1] ) {
      version = vers[1];
      concludedUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    } else if( res =~ "^HTTP/1\.[01] 401" && "Access to this page is restricted" >< res ) {
      extra = "The Web Console is protected by a password.";
      set_kb_item( name:"www/content/auth_required", value:TRUE );
      set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/a:lynxtechnology:twonky_server:" );
    if( ! cpe )
      cpe = "cpe:/a:lynxtechnology:twonky_server";

    set_kb_item( name:"twonky/server/detected", value:TRUE );
    set_kb_item( name:"twonky/server/http/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Twonky Server",
                                              version:version,
                                              install:install,
                                              extra:extra,
                                              cpe:cpe,
                                              concluded:vers[0],
                                              concludedUrl:concludedUrl ),
                 port:port );
  }
}

exit( 0 );
