# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125495");
  script_version("2025-11-14T15:41:06+0000");
  script_tag(name:"last_modification", value:"2025-11-14 15:41:06 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-13 16:19:57 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle Application Testing Suite Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Oracle Application Testing Suite detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_oracle_oats_http_detect.nasl", "gb_oracle_oats_smb_login_detect.nasl");
  script_mandatory_keys("oracle/application_testing_suite/detected");

  script_xref(name:"URL", value:"https://www.oracle.com/enterprise-manager/downloads/oats-downloads.html");

  exit(0);
}

if( ! get_kb_item( "oracle/application_testing_suite/detected" ) )
  exit( 0 );

include("cpe.inc");
include("host_details.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "http", "smb-login" ) ) {

  install_list = get_kb_list( "oracle/application_testing_suite/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclurl = infos[4];
    extra    = infos[5];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:oracle:application_testing_suite:" );
    if( ! cpe )
      cpe = "cpe:/a:oracle:application_testing_suite";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Oracle Application Testing Suite",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      extra:extra,
                                      concludedUrl:conclurl,
                                      concluded:concl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
