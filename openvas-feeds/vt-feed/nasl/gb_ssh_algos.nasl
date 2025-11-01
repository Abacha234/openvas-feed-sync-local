# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105565");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2016-03-09 08:39:30 +0100 (Wed, 09 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Protocol Algorithms Supported");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"This script detects which algorithms are supported by the remote
  SSH service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("byte_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("list_array_func.inc");

port = ssh_get_port( default:22 );

# nb:
# - When adding more algorithms here please make sure to also adjust / extend the insight tag of the
#   following accordingly:
#   - 2025/gb_ssh_pqc_kex_algo_missing.nasl
#   - 2025/gb_ssh_pqc_kex_algo_supported.nasl
# - https://www.forescout.com/blog/post-quantum-cryptography-the-real-risks-of-not-adopting-it/ has
#   a list of current algorithms
pqc_algos_list = make_list(
  "sntrup761x25519-sha512@openssh.com",
  "sntrup761x25519-sha512",
  "mlkem768x25519-sha256",
  "sntrup4591761x25519-sha512@tinyssh.org",
  "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org",
  "ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org",
  "ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org",
  "x25519-kyber-512r3-sha256-d00@amazon.com",
  "mlkem1024nistp384-sha384",
  "mlkem768nistp256-sha256",
  "curve25519-frodokem1344-sha512@ssh.com",
  "ecdh-nistp521-kyber1024-sha512@ssh.com",

  # nb: To be on the safe side the ones below without the "@" if not already included as some
  # specific SSH server implementations might handle it differently.
  "sntrup4591761x25519-sha512",
  "ecdh-nistp256-kyber-512r3-sha256-d00",
  "ecdh-nistp384-kyber-768r3-sha384-d00",
  "ecdh-nistp521-kyber-1024r3-sha512-d00",
  "x25519-kyber-512r3-sha256-d00",
  "curve25519-frodokem1344-sha512",
  "ecdh-nistp521-kyber1024-sha512"
);

types = make_list(
  "kex_algorithms",
  "server_host_key_algorithms",
  "encryption_algorithms_client_to_server",
  "encryption_algorithms_server_to_client",
  "mac_algorithms_client_to_server",
  "mac_algorithms_server_to_client",
  "compression_algorithms_client_to_server",
  "compression_algorithms_server_to_client");

if( ! sock = open_sock_tcp( port ) )
  exit( 0 );

server_version = ssh_exchange_identification( socket:sock );
if( ! server_version ) {
  close( sock );
  exit( 0 );
}

buf = ssh_recv( socket:sock, length:2000 );
close( sock );

if( isnull( buf ) )
  exit( 0 );

blen = strlen( buf );
if( blen < 40 )
  exit( 0 );

if( ord( buf[5] ) != 20 )
  exit( 0 );

pos = 22;
pqc_algo_available = FALSE;

foreach type( types ) {

  if( pos + 4 > blen )
    break;

  len = getdword( blob:buf, pos:pos );
  pos += 4;

  if( pos + len > blen )
    exit( 0 );

  options = substr( buf, pos, pos + len - 1 );
  pos += len;

  if( ! options )
    continue;

  str = split( options, sep:",", keep:FALSE );

  foreach algo( str ) {
    set_kb_item( name:"ssh/" + port + "/" + type, value:algo );

    # nb: PQC algorithms are currently only expected for this one.
    if( type == "kex_algorithms" ) {
      if( in_array( search:algo, array:pqc_algos_list, part_match:FALSE ) ) {
        pqc_algo_available = TRUE;
        set_kb_item( name:"ssh/" + port + "/pqc_kex_algorithms", value:algo );
      }
    }
  }

  report += type + ':\n' + options + '\n\n';
}

# nb:
# - Store the reference from this one to some VTs like e.g. gb_ssh_weak_host_key_algos.nasl using
#   the info collected here to show a cross-reference within the reports
# - We're not using register_product() here as we don't want to register the protocol within this
#   VT (as the CPEs are already registered in ssh_proto_version.nasl) by but just want to make use
#   of the functionality to show the reference in the reports
# - Also using only the SSH2 relevant CPE here on purpose (and not the SSH1 one) just to have one
#   more generic assigned
# - If changing the syntax of e.g. the port + "/tcp" below make sure to update VTs like e.g. the
#   gb_ssh_weak_host_key_algos.nasl accordingly
register_host_detail( name:"SSH Protocol Algorithms Supported", value:"cpe:/a:ietf:secure_shell_protocol" );
register_host_detail( name:"cpe:/a:ietf:secure_shell_protocol", value:port + "/tcp" );
register_host_detail( name:"port", value:port + "/tcp" );

# Used in ssh_login_failed to evaluate if the SSH server is using unsupported algorithms
set_kb_item( name:"ssh/" + port + "/algos_available", value:TRUE );

set_kb_item( name:"ssh/algos_available", value:TRUE );

# nb: For use in the following:
# - 2025/gb_ssh_pqc_kex_algo_missing.nasl
# - 2025/gb_ssh_pqc_kex_algo_supported.nasl
if( pqc_algo_available ) {
  set_kb_item( name:"ssh/" + port + "/pqc_algos_supported", value:TRUE );
  set_kb_item( name:"ssh/pqc_algos_supported", value:TRUE );
} else {
  set_kb_item( name:"ssh/" + port + "/pqc_algos_missing", value:TRUE );
  set_kb_item( name:"ssh/pqc_algos_missing", value:TRUE );
}

report = 'The following options are supported by the remote SSH service:\n\n' + report;

log_message( port:port, data:chomp( report ) );
exit( 0 );
