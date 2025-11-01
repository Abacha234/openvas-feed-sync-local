# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112138");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-11-23 11:04:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OPENVAS SCAN / Greenbone Enterprise Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of OPENVAS SCAN / Greenbone Enterprise
  Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

if( ! sysdesc = snmp_get_sysdescr( port:port ) )
  exit( 0 );

# nb: As of GOS 24.10.6 the OPENVAS SCAN appliance is still reporting itself as "Greenbone Enterprise Appliance".
if( concl = egrep( pattern:"^Greenbone (Security Manager|Enterprise Appliance)", string:sysdesc, icase:FALSE ) ) {

  type = "unknown";
  version = "unknown";

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/snmp/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/snmp/port", value:port );

  concluded = "    " + chomp( concl );
  concludedOID = "    1.3.6.1.2.1.1.1.0 (sysDescr)";

  # This OID should contain both the GSM type and GOS version but was only available on older GOS
  # versions.
  info_oid = "1.3.6.1.2.1.1.5.0";
  oid_res = snmp_get( port:port, oid:info_oid );

  # nb: Keep in sync with the pattern in gb_greenbone_os_consolidation.nasl
  type_nd_vers = eregmatch( pattern:"^([0-9]+|BASIC|FREE|TRIAL|DEMO|ONE|MAVEN|150V|EXPO|25V|CE|CENO|DECA|TERA|PETA|EXA)-([0-9\-]+)", string:oid_res, icase:TRUE );
  if( ! isnull( type_nd_vers[1] ) && ! isnull( type_nd_vers[2] ) ) {
    # nb: Products are named uppercase
    type = toupper( type_nd_vers[1] );
    version = str_replace( string:type_nd_vers[2], find:"-", replace:"." );
    concluded = '\n    ' + concluded;
    concludedOID = '\n    ' + concludedOID;
  }

  # nb: Newer versions are using a different OID tree which seems to be also only available if
  # SNMPv3 is enabled / configured.
  if( type == "unknown" ) {
    info_oid = "1.3.6.1.4.1.35847.1.2.1";
    oid_res = snmp_get( port:port, oid:info_oid );

    # e.g.:
    # Greenbone Enterprise deca
    if( oid_res && oid_res =~ "^Greenbone Enterprise .+" ) {
      _type = eregmatch( string:oid_res, pattern:"^Greenbone Enterprise (.+)", icase:FALSE );
      if( _type[1] ) {
        # nb: Same as above
        type = toupper( _type[1] );
        concluded += '\n    ' + oid_res;
        concludedOID += '\n    ' + info_oid + " (hwName)";
      }
    }
  }

  if( version == "unknown" ) {
    info_oid = "1.3.6.1.4.1.35847.1.3.2.1";
    oid_res = snmp_get( port:port, oid:info_oid );

    # e.g.:
    # 22.04.22
    # 24.10.6
    if( oid_res && oid_res =~ "^[0-9.]+$" ) {
      _vers = eregmatch( string:oid_res, pattern:"^([0-9.]+)$", icase:FALSE );
      if( _vers[1] ) {
        version = _vers[1];
        concluded += '\n    ' + oid_res;
        concludedOID += '\n    ' + info_oid + " (swVersionString)";
      }
    }
  }

  set_kb_item( name:"greenbone/gos/snmp/" + port + "/version", value:version );
  set_kb_item( name:"greenbone/gsm/snmp/" + port + "/type", value:type );
  set_kb_item( name:"greenbone/gos/snmp/" + port + "/concludedOID", value:concludedOID );
  set_kb_item( name:"greenbone/gos/snmp/" + port + "/concluded", value:concluded );
}

exit( 0 );
