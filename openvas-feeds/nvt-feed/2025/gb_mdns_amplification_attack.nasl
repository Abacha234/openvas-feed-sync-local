# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119234");
  script_version("2025-11-27T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-11-27 05:40:40 +0000 (Thu, 27 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-25 12:42:50 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("mDNS Service Amplification Attack (UDP) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_dependencies("mdns_service_detection.nasl", "global_settings.nasl");
  script_require_udp_ports("Services/udp/mdns", 5353);
  script_mandatory_keys("mdns/udp/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Reaktion/CERT-Bund/CERT-Bund-Reports/HowTo/Offene-mDNS-Dienste/Offene-mDNS-Dienste_node.html");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/550620");
  script_xref(name:"URL", value:"https://github.com/chadillac/mdns_recon");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Mar/164");
  script_xref(name:"URL", value:"https://vercara.digicert.com/resources/multicast-dns-mdns-amplification-ddos");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks");

  script_tag(name:"summary", value:"A publicly accessible service supporting the Multicast DNS
  (mDNS) protocol can be exploited to participate in a Distributed Denial of Service (DDoS)
  attack.");

  script_tag(name:"vuldetect", value:"Sends a crafted UDP request and checks the response size.

  Notes:

  - This VT is only reporting a vulnerability if the target system / service is accessible from a
    public WAN (Internet) / public LAN.

    A configuration option 'Network type' to define if a scanned network should be seen as a public
    LAN can be found in the preferences of the following VT:

    Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)

  - No scan result is expected if localhost (127.0.0.1) was scanned (self scanning)");

  script_tag(name:"insight", value:"An Amplification attack is a popular form of Distributed Denial
  of Service (DDoS) that relies on the use of publicly accessible mDNS services to overwhelm a
  victim system with response traffic.

  The basic attack technique consists of an attacker sending a valid query request to a mDNS service
  with the source address spoofed to be the victim's address. When the mDNS service sends the
  response, it is sent instead to the victim. Attackers will typically first inserting records into
  the open server to maximize the amplification effect. Because the size of the response is
  typically considerably larger than the request, the attacker is able to amplify the volume of
  traffic directed at the victim. By leveraging a botnet to perform additional spoofed queries, an
  attacker can produce an overwhelming amount of traffic with little effort. Additionally, because
  the responses are legitimate data coming from valid clients, it is especially difficult to block
  these types of attacks.");

  script_tag(name:"solution", value:"The following mitigation possibilities are currently available:

  - Disable public access to the UDP port of this mDNS service

  - Configure the mDNS service to only listen on localhost

  - Disable the service if unused / not required");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("port_service_func.inc");
include("network_func.inc");
include("misc_func.inc");
include("dump.inc");
include("mdns_func.inc");

if( ! is_public_addr() )
  exit( 0 );

port = service_get_port( default:5353, proto:"mdns", ipproto:"udp" );

if( ! get_kb_item( "mdns/udp/" + port + "/detected" ) )
  exit( 0 );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

transactionId = 0x4a;
list_services = mdns_create_service_list();

if( isnull( query_services = mdns_list_to_qname_query( labels:list_services ) ) ) {
  close( soc );
  exit( 0 );
}

if( isnull( req = mdns_create_query( query:query_services, itype:"PTR", transactionId:transactionId ) ) ) {
  close( soc );
  exit( 0 );
}

send( socket:soc, data:req );
res = recv( socket:soc, length:1024 );
close( soc );

# nb: Just some basic verification
if( ! res || strlen( res ) < 8 )
  exit( 0 );

res_str = bin2string( ddata:res, noprint_replacement:' ' );
# nb: And a few additional verifications to just match on valid responses like e.g.:
#
# _services _dns-sd _udp local            _googlecast _tcp #             _googcrossdevice @             _googlezone @
#
# _services _dns-sd _udp local                  _smb _tcp #             _ftp ?             _http ?             _afpovertcp ?             _device-info ?
if( res_str !~ "(_services|_dns-sd|_udp|local|_tcp|_smb|_ftp|_http)" )
  exit( 0 );

req_len = strlen( req );
res_len = strlen( res );

# mdns_recon tool readme says:
#
# > An attacker can expect at least a 1:1 reflection, in some of my testing, some services amplified
#   by as much as 975%. The true amplification rate is hard to predict since the replies vary a lot
#   based on server configuration and the size of the query packet itself, which changes based on
#   the service being queried, but a safe estimate would be around 130%+ amplifcation on average.
#
# As we don't want to query all services a factor of 2 should be enough to proof the reflection
# attack possibility.
#
if( res_len > ( 2 * req_len ) ) {
  report = 'We have sent a query request of ' + req_len + ' bytes and received a response of ' + res_len + ' bytes.';
  security_message( port:port, data:report, proto:"udp" );
  exit( 0 );
}

exit( 99 );
