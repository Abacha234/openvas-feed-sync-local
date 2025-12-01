# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119233");
  script_version("2025-11-27T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-11-27 05:40:40 +0000 (Thu, 27 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-25 09:11:03 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("mDNS Service Public WAN (Internet) Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("mdns_service_detection.nasl", "global_settings.nasl");
  script_require_udp_ports("Services/udp/mdns", 5353);
  script_mandatory_keys("mdns/udp/info_accessible");
  script_exclude_keys("keys/is_private_addr", "keys/is_private_lan_or_wan");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Reaktion/CERT-Bund/CERT-Bund-Reports/HowTo/Offene-mDNS-Dienste/Offene-mDNS-Dienste_node.html");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/550620");
  script_xref(name:"URL", value:"https://github.com/chadillac/mdns_recon");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Mar/164");
  script_xref(name:"URL", value:"https://vercara.digicert.com/resources/multicast-dns-mdns-amplification-ddos");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks");

  script_tag(name:"summary", value:"The script checks if the target host is exposing a service
  supporting the Multicast DNS (mDNS) protocol to a Public WAN (Internet).");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is exposing a service supporting
  the mDNS protocol to a public WAN (Internet) based on the information collected by the VT 'mDNS
  Service Detection (UDP)' (OID: 1.3.6.1.4.1.25623.1.0.101013).

  Notes:

  - The scanner has no possibility to determine if a target system is located in a private LAN /
    private WAN. If the target is located in such a network please set the 'Network type'
    configuration of the following VT to e.g. 'Private LAN' or 'Private WAN':

    Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)

  - No scan result is expected if localhost (127.0.0.1) was scanned (self scanning)");

  script_tag(name:"insight", value:"A public accessible mDNS service is generally seen as / assumed
  to be a security misconfiguration.");

  script_tag(name:"impact", value:"Responses may disclose information about network devices or be
  used in denial of service (DoS) amplification attacks.");

  script_tag(name:"solution", value:"- Disable public access to the mDNS service or only allow
  access from trusted sources

  - Disable the service if unused / not required");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");
include("port_service_func.inc");

# nb: is_public_addr() is not used here as we don't want to report for e.g. "Public LAN" or
# "Private WAN" which should be fine.
if( is_private_addr() || net_setting_is_private_lan_or_wan() )
  exit( 0 );

port = service_get_port( default:5353, proto:"mdns", ipproto:"udp" );

if( ! get_kb_item( "mdns/udp/" + port + "/info_accessible" ) )
  exit( 0 );

# nb:
# - Store the reference from this one to dns_server.nasl to show a cross-reference within the
#   reports
# - We don't want to / can't use get_app_* functions and we're only interested in the
#   cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.101013" ); # mdns_service_detection.nasl
register_host_detail( name:"detected_at", value:port + "/udp" );

security_message( port:port, data:"A service supporting the mDNS protocol is publicly accessible.", proto:"udp" );
exit( 0 );
