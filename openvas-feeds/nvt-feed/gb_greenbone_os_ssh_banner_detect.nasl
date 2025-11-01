# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119149");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-14 10:34:09 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OPENVAS SCAN / Greenbone Enterprise Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS) (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/greenbone/gos/detected");

  script_tag(name:"summary", value:"SSH banner-based detection of OPENVAS SCAN / Greenbone
  Enterprise Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

banner = ssh_get_serverbanner( port:port );

# SSH-2.0-Greenbone_7.9p2gb Greenbone OS 21.04
# SSH-2.0-Greenbone_8.4p2gb Greenbone OS 22.04
# SSH-2.0-Greenbone_9.2p1gb Greenbone OS 24.10
if( banner && "Greenbone OS" >< banner ) {

  version = "unknown";

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/ssh-banner/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/ssh-banner/port", value:port );

  vers = eregmatch( pattern:"Greenbone OS ([0-9.-]+)", string:banner );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  set_kb_item( name:"greenbone/gos/ssh-banner/" + port + "/version", value:version );
  set_kb_item( name:"greenbone/gos/ssh-banner/" + port + "/concluded", value:"    " + chomp( banner ) );
}

exit( 0 );
