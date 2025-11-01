# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107337");
  script_version("2025-10-10T15:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-10 15:40:56 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2018-09-06 14:43:30 +0200 (Thu, 06 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Docker for Windows Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Docker for Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! app_name || app_name !~ "Docker for Windows" )
      continue;

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    if( loc = registry_get_sz( key:key + item, item:"InstallLocation" ) )
      location = loc;

    # This VT covers the old versioning e.g.  18.06.0-ce-rc3-win68
    # New versioning e.g. '2.0.0.2' for actual installations is covered by
    # '1.3.6.1.4.1.25623.1.0.107680' Docker Desktop Detection (Windows SMB Login)

    if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      version = vers;
      concluded += '\nDisplayVersion: ' + vers;
    }

    # The key 'ChannelName' distinguishes between 'stable' and unstable ('edge') releases
    if( buildVer = registry_get_sz( key:key + item, item:"ChannelName" ) ) {
      build = buildVer;
      concluded += '\nBuild: ' + build;
    }

    set_kb_item( name:"docker/docker_for_windows/detected", value:TRUE );
    set_kb_item( name:"docker/docker_for_windows/smb-login/detected", value:TRUE );
    set_kb_item( name:"docker/docker_for_windows/build", value:build );

    register_and_report_cpe( app:app_name, ver:version, concluded:concluded,
                             base:"cpe:/a:docker:docker:", expr:"^([0-9.a-z-]+)", insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
