# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.129018");
  script_version("2025-12-01T05:45:26+0000");
  script_tag(name:"last_modification", value:"2025-12-01 05:45:26 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-11-26 08:00:00 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Microsoft Windows Extended Security Updates(ESU) Status Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of the Microsoft Windows Extended
  Security Updates(ESU) status.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("powershell_func.inc");

if ( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) {
  set_kb_item( name:"Microsoft/Windows/ESUStatus", value:"There is no active ESU program for this OS" );
  exit( 0 );
}

if(hotfix_check_sp(win10:1, win10x64:1, win2012:1, win2012R2:1) <= 0) {
  set_kb_item( name:"Microsoft/Windows/ESUStatus", value:"No active ESU license" );
  exit(0);
}

# getting esu status
ps_get_esu_info = "Get-CimInstance -Query \" + '"' + "select Name,ID,LicenseStatus from softwarelicensingproduct where name like '" + '%' + "ESU" + '%' + "' and licensestatus = '1'\" + '"' + " | sort Name | foreach { $_.id + ';' + $_.name }";
esu_info = powershell_cmd( cmd:ps_get_esu_info );

if ( !esu_info ) {
  exit( 0 );
}

# Valid license IDs
win10_y1 = "f520e45e-7413-4a34-a497-d2765967d094";
win10_y2 = "1043add5-23b1-4afb-9a0f-64343c8f3f8d";
win10_y3 = "83d49986-add3-41d7-ba33-87c7bfb5c0fb";

server2012_y1 = "c0a2ea62-12ad-435b-ab4f-c9bfab48dbc4";
server2012_y2 = "e3e2690b-931c-4c80-b1ff-dffba8a81988";
server2012_y3 = "55b1dd2d-2209-4ea0-a805-06298bad25b3";

em_server_y1 = "5f7d1147-3adc-4b28-8e57-4713ab7623cd";
em_server_y2 = "050b873b-763b-437b-b7c5-9efbeb96ae32";
em_server_y3 = "d44f8a8e-5129-4999-9fe0-5025c2341033";

valid_ids = make_list(win10_y1,win10_y2,win10_y3,
                      server2012_y1,server2012_y2,server2012_y3,
                      em_server_y1,em_server_y2,em_server_y3);

# Example: f520e45e-7413-4a34-a497-d2765967d094;Windows(R), Client-ESU-Year1 add-on for Education,EducationN,...
pattern = "^([^;]*);.* ([a-zA-Z0-9]*-ESU-[a-zA-Z0-9]*) .*";

foreach product( split( egrep( string:esu_info, pattern:pattern ) ) ) {
  value = eregmatch( string:product, pattern:pattern );

  license_id = value[1];
  program_name = value[2];

  foreach license ( valid_ids ) {
    if ( license >< license_id ) {
      valid_license_found = TRUE;
      esu_status += program_name + "(" + license_id + ");";
      break;
    }
  }
}

if ( !valid_license_found )
  esu_status = "Unknown license";

if ( !esu_status )
  set_kb_item( name:"Microsoft/Windows/ESUStatus", value:"No active ESU license" );

set_kb_item( name:"Microsoft/Windows/ESUStatus", value:esu_status );


exit( 0 );