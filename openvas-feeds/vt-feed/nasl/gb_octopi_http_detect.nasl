# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107343");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2018-10-11 16:21:34 +0200 (Thu, 11 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OctoPi Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the OctoPi Raspberry Pi distribution for
  3D printers.");

  script_xref(name:"URL", value:"https://octoprint.org/download/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );
buf = http_get_cache( item:"/", port:port );

# Basic realm="Octopi Interface"
# Basic realm="OctoPi"
# WWW-Authenticate: Basic realm="octopi"
if( concl = egrep( string:banner, pattern:'^WWW-Authenticate\\s*:\\s*Basic realm="OctoPi( Interface)?"', icase:TRUE ) ) {
  octopi_auth_found = TRUE;
  concluded = "  " + chomp( concl );
  found = TRUE;
}

# <title>OctoPrint Login</title>
# <title data-bind="text: title">OctoPrint</title>
if( ( concl = eregmatch( string:buf, pattern:"<title[^>]*>OctoPrint[^>]*</title>", icase:FALSE ) ) && "plugin_octopi_support_version" >< buf ) {
  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];
  concluded += '\n  plugin_octopi_support_version';
  found = TRUE;
}

if( found ) {

  install = "/";
  conclUrl = "  " + http_report_vuln_url( port:port, url:install, url_only:TRUE );
  version = "unknown";

  if( octopi_auth_found ) {
    set_kb_item( name:"octopi/http/" + port + "/auth", value:TRUE );
    set_kb_item( name:"octopi/http/auth", value:TRUE );
  } else {
    set_kb_item( name:"octopi/http/" + port + "/noauth", value:TRUE );
    set_kb_item( name:"octopi/http/noauth", value:TRUE );
  }

  set_kb_item( name:"octopi/detected", value:TRUE );
  set_kb_item( name:"octopi/http/detected", value:TRUE );
  set_kb_item( name:"octopi/http/port", value:port );

  # <p>Version <span class="plugin_octopi_support_version">0.13.0</span></p>
  # <p>Version <span class="plugin_octopi_support_version">0.14.0</span></p>
  vers = eregmatch( pattern:'<span class="plugin_octopi_support_version">([0-9.]+)</span>', string:buf, icase:TRUE );
  if( vers[1] ) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
  }

  os_register_and_report( os:"OctoPi Raspberry Pi Distribution", version:version, cpe:"cpe:/o:octoprint:octopi", banner_type:"HTTP WWW-Authenticate banner / HTTP Interface", port:port, desc:"OctoPi Detection (HTTP)", runs_key:"unixoide" );

  register_and_report_cpe( app:"OctoPi Raspberry Pi Distribution", ver:version, concluded:concluded, base:"cpe:/o:octoprint:octopi:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www", conclUrl:conclUrl );
}

exit( 0 );
