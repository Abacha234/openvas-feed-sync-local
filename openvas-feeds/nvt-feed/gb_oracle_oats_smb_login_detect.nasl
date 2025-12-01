# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107485");
  script_version("2025-11-14T15:41:06+0000");
  script_tag(name:"last_modification", value:"2025-11-14 15:41:06 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2019-01-29 14:44:33 +0100 (Tue, 29 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Oracle Application Testing Suite Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Oracle Application Testing Suite.");

  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/oem/app-test/etest-101273.html");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

port = kb_smb_transport();

key_list = make_list( "SYSTEM\CurrentControlSet\Services\" );
if( isnull( key_list ) )
  exit( 0 );

foreach key ( key_list ) {
  foreach item ( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    if( !app_name || app_name !~ "Oracle ATS Server" )
      continue;

    version = "unknown";
    concluded = app_name;
    location = "unknown";

    loc = registry_get_sz( key:key + item, item:"ImagePath" );
    if( loc ) {
      split = split( loc, sep:"\" );
      max = max_index( split ) - 1;
      string = split[max - 4] + "\" + split[max - 3] + "\" + split[max - 2] + "\" + split[max - 1] + "\" + split[max];

      location = ereg_replace( string:loc, pattern:string, replace:'' );
      path = location + "config\version.properties";

      version_info = smb_read_file( fullpath:path, offset:0, count:3000 );
      if( version_info ) {
        vers = eregmatch( pattern:"oracle.version.build=([0-9.]+)", string:version_info );
        if( vers ) {
          version = vers[1];
          if ( strip_vers = eregmatch( pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)", string: version ) )
            version = strip_vers[0];
          concluded = "Version " + version + " extracted from " + path + " (" + vers[0] + ")";
        }
      }
    }

    set_kb_item( name:"oracle/application_testing_suite/detected", value:TRUE );
    set_kb_item( name:"oracle/application_testing_suite/smb-login/detected", value:TRUE );

    set_kb_item( name:"oracle/application_testing_suite/smb-login/" + port + "/installs",
                 value:"0#---#" + location + "#---#" + version + "#---#" + concluded );

    exit( 0 );
  }
}

exit( 0 );
