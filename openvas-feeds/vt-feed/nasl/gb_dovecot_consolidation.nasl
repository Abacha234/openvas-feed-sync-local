# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113212");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2018-06-26 11:11:11 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dovecot Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sw_dovecot_pop3_imap_detect.nasl", "gb_dovecot_ssh_login_detect.nasl");
  script_mandatory_keys("dovecot/detected");

  script_xref(name:"URL", value:"https://www.dovecot.org/");

  script_tag(name:"summary", value:"Consolidation of Dovecot detections.");

  # nb: Vulnerable version checks will have to be unreliable, as backports exist:
  # https://packages.debian.org/search?searchon=sourcenames&keywords=dovecot
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "dovecot/detected" ) )
  exit( 0 );

base_cpe = "cpe:/a:dovecot:dovecot";
report   = ""; # nb: To make openvas-nasl-lint happy...

info_list = get_kb_list( "dovecot/detection-info" );
if( ! info_list )
  exit( 0 );

# Sort to not report changes on delta reports if just the order is different
info_list = sort( info_list );

foreach info( info_list ) {

  _info_list = split( info, sep:"#--#", keep:FALSE );
  if( max_index( _info_list ) != 6 )
    continue; # Something went wrong and not all required infos are there...

  # Format set by gb_dovecot_ssh_login_detect.nasl and sw_dovecot_pop3_imap_detect.nasl is:
  # Detection-Name#--#service#--#port#--#location#--#version#--#concluded
  name      = _info_list[0];
  service   = _info_list[1];
  port      = _info_list[2];
  location  = _info_list[3];
  version   = _info_list[4];
  concluded = _info_list[5];

  if( version != "unknown" )
    cpe = base_cpe + ":" + version;
  else
    cpe = base_cpe;

  register_product( cpe:cpe, location:location, port:port, service:service );

  if( report )
    report += '\n\n';

  report += build_detection_report( app:"Dovecot",
                                    version:version,
                                    install:location,
                                    cpe:cpe,
                                    concluded:concluded );
  report += '\n\nDetection Method: ' + name;
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
