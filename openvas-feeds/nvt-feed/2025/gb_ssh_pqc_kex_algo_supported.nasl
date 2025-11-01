# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119215");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-29 11:56:43 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PQC Key Exchange (KEX) Algorithm(s) Supported (SSH)");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/pqc_algos_supported");

  script_xref(name:"URL", value:"https://openssh.com/pq.html");
  script_xref(name:"URL", value:"https://quantumcomputingreport.com/openssh-10-0-introduces-default-post-quantum-key-exchange-algorithm/");
  script_xref(name:"URL", value:"https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards");
  script_xref(name:"URL", value:"https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved");
  script_xref(name:"URL", value:"https://www.forescout.com/blog/post-quantum-cryptography-the-real-risks-of-not-adopting-it/");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow / support at least
  ONE Post-Quantum Cryptography (PQC) key exchange (KEX) algorithm(s).");

  # nb: When adding more algorithms here please make sure to also adjust / extend the following
  # accordingly:
  # - 2025/gb_ssh_pqc_kex_algo_missing.nasl
  # - gb_ssh_algos.nasl
  script_tag(name:"vuldetect", value:"Checks the (previously collected) supported KEX algorithms of
  the remote SSH server.

  Currently the following PQC KEX algorithms are defined / getting used for this check:

  - sntrup761x25519-sha512@openssh.com

  - sntrup761x25519-sha512

  - mlkem768x25519-sha256

  - sntrup4591761x25519-sha512@tinyssh.org

  - ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org

  - ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org

  - ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org

  - x25519-kyber-512r3-sha256-d00@amazon.com

  - mlkem1024nistp384-sha384

  - mlkem768nistp256-sha256

  - curve25519-frodokem1344-sha512@ssh.com

  - ecdh-nistp521-kyber1024-sha512@ssh.com");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ssh_get_port( default:22 );

if( ! get_kb_item( "ssh/" + port + "/pqc_algos_supported" ) )
  exit( 0 );

if( ! pqc_kex_algos = get_kb_list( "ssh/" + port + "/pqc_kex_algorithms" ) )
  exit( 0 );

# nb: Sorting to not cause any diff on delta reports if just the order changes...
pqc_kex_algos = sort( pqc_kex_algos );

# nb:
# - Store the reference from this one to gb_ssh_algos.nasl to show a cross-reference within the
#   reports
# - We don't want to use get_app_* functions as we're only interested in the cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.105565" ); # gb_ssh_algos.nasl
register_host_detail( name:"detected_at", value:port + "/tcp" );

report = "The remote SSH server supports the following PQC KEX algorithm(s):";

foreach pqc_kex_algo( pqc_kex_algos )
  report += '\n - ' + pqc_kex_algo;

log_message( port:port, data:report );
exit( 0 );
