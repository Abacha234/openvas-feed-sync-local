# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100208");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Name Server Daemon (NSD) Detection (DNS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("dns_server_tcp.nasl", "dns_server.nasl");
  script_mandatory_keys("dns/server/detected");

  script_xref(name:"URL", value:"http://www.nlnetlabs.nl/projects/nsd/");

  script_tag(name:"summary", value:"DNS (TCP and UDP) based detection of the Name Server Daemon
  (NSD).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto;
  local_var version, ver, cpe;

  if( ! data || "nsd" >!< tolower( data ) )
    return;

  version = "unknown";
  ver = eregmatch( pattern:"NSD ([0-9.]+)", string:data, icase:TRUE );
  if( ver[1] )
    version = ver[1];

  set_kb_item( name:"nsd/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nlnetlabs:nsd:" );
  if( ! cpe )
    cpe = "cpe:/a:nlnetlabs:nsd";

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto, service:"domain" );
  log_message( data:build_detection_report( app:"Name Server Daemon (NSD)",
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:data ),
               port:port,
               proto:proto );
}

udp_ports = get_kb_list( "DNS/udp/version_request" );
foreach port( udp_ports ) {

  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"udp" );
}

tcp_ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_ports ) {

  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );
