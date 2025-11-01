# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806810");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2016-01-04 13:14:29 +0530 (Mon, 04 Jan 2016)");
  script_name("Knot DNS Server Detection (DNS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("dns_server_tcp.nasl", "dns_server.nasl");
  script_mandatory_keys("dns/server/detected");

  script_tag(name:"summary", value:"DNS (TCP and UDP) based detection of the Knot DNS Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto;
  local_var version, ver, cpe;

  if( ! data || "knot dns" >!< tolower( data ) )
    return;

  version = "unknown";
  ver = eregmatch( pattern:"Knot DNS ([0-9A-Z.-]+)", string:data, icase:TRUE );
  if( ver[1] )
    version = ver[1];

  cpe = build_cpe( value:version, exp:"^([0-9/.]+)", base:"cpe:/a:knot:dns:" );
  if( ! cpe )
    cpe = "cpe:/a:knot:dns";

  set_kb_item( name:"knotdns/detected", value:TRUE );

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto, service:"domain" );
  log_message( data:build_detection_report( app:"Knot DNS",
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:ver[0] ),
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
