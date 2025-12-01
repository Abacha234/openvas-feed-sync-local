# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900510");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-11-25T05:40:35+0000");
  script_tag(name:"last_modification", value:"2025-11-25 05:40:35 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("RaidenFTPD Server Version Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_gather_service_list_win.nasl");

  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed version of RaidenFTPD Server.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM"){
  if( get_kb_item( "SMB/gather_service_list_win/error" ) )
    exit( 0 );

  if( ! service_list = get_kb_item( "SMB/gather_service_list_win/services" ) )
    exit( 0 );

}else{
  cmd = "Get-CimInstance -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'RaidenFTPDService'} | foreach-object {$_.DisplayName + ';' + $_.Name + ';' + $_.State + ';' + $_.ServiceType + ';' + $_.StartMode + ';' + $_.PathName + ';' }";
  service_list = powershell_cmd( cmd:cmd );
  if( ! service_list )
    exit( 0 );

}


#RaidenFTPDService;RaidenFTPDService;Stopped;Own Process;Manual;C:\RaidenServer\RaidenFTPD\rfsvc.exe;
pattern = "(^RaidenFTPDService[^;]*);([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);";
if( service_info_found = egrep( string:service_list, pattern:pattern ) ) {
  value = eregmatch( string:service_info_found, pattern:pattern );

  display_name = value[1];
  start_type = value[5];
  install_location = value[6];

  if( ! install_location ) {
    insloc_cmd = "(Get-ItemProperty 'Microsoft.PowerShell.Core\Registry::HKLM\System\CurrentControlSet\Services\RaidenFTPDService\' -ErrorAction SilentlyContinue).ImagePath";
    install_location = powershell_cmd( cmd:insloc_cmd );
    if( ! install_location )
      exit( 0 );
    install_location = install_location - "rfsvc.exe";
  }

  exe_path = install_location + "raidenftpd.exe";
  version_cmd = "(Get-itemproperty '" + exe_path + "' -ErrorAction SilentlyContinue).VersionInfo.FileVersion -replace(', ','.')";
  version = powershell_cmd( cmd:version_cmd );
  if( ! version )
    exit( 0 );

  concluded += "  Service name:  " + display_name;
  concluded += '\n  Start Type:    ' + start_type;

  set_kb_item( name:"RaidenFTPD/detected", value:TRUE );
  set_kb_item( name:"RaidenFTPD/smb-login/detected", value:TRUE );

  register_and_report_cpe( app:"RaidenFTPD", ver:version, concluded:concluded,
                          base:"cpe:/a:raidenftpd:raidenftpd:", expr:"^([0-9.]+)", insloc:install_location, regService:"smb-login", regPort:0 );

}

exit( 0 );