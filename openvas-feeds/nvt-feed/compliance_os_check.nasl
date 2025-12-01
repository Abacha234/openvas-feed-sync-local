# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131771");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-18 08:44:21 +0000 (Tue, 18 Nov 2025)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Determine Linux OS for compliance development");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "ssh_authorization.nasl");
  script_mandatory_keys("Compliance/Launch", "login/SSH/success");

  script_tag(name:"summary", value:"This script will, if given a userid/password or
  key to the remote system, login to that system, determine if the OS is Linux, and for
  supported systems collect and save OS release.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

uname = ssh_cmd( socket:sock, cmd:"uname -s", return_errors:TRUE );
if( uname == "Linux" )
  set_kb_item( name:"policy/linux_system/detected", value:TRUE );

rls = ssh_cmd( socket:sock, cmd:"cat /etc/os-release", return_errors:FALSE );
if (rls){
  if( rls =~ 'NAME="EulerOS"' ) {
     _rls = ssh_cmd( socket:sock, cmd:"cat /etc/uvp-release", return_errors:FALSE );
    if( _rls =~ "EulerOS Virtualization" ) {
      # EulerOSVirtual keys for compliance development
      set_kb_item( name:"policy/ssh/login/eulerosvirtual", value:TRUE );
      set_kb_item( name:"policy/ssh/login/eulerosvirtual_openeuler", value:TRUE );
      set_kb_item( name:"policy/ssh/login/eulerosvirtual_openeuler_hce", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler_hce", value:TRUE );
      set_kb_item( name:"policy/ssh/login/os-release", value:_rls );
    } else {
      # EulerOS keys for compliance development
      set_kb_item( name:"policy/ssh/login/euleros", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_openeuler", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_openeuler_hce", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler_hce", value:TRUE );
      release = ssh_cmd( socket:sock, cmd:"cat /etc/euleros-release", return_errors:FALSE );
      if( release )
        set_kb_item( name:"policy/ssh/login/os-release", value:release );
    }
  }

  # OpenEuler keys for compliance development
  if( rls =~ 'NAME="openEuler"' ) {
    set_kb_item( name:"policy/ssh/login/openeuler", value:TRUE );
    set_kb_item( name:"policy/ssh/login/openeuler_hce", value:TRUE );
    set_kb_item( name:"policy/ssh/login/euleros_openeuler", value:TRUE );
    set_kb_item( name:"policy/ssh/login/eulerosvirtual_openeuler", value:TRUE );
    set_kb_item( name:"policy/ssh/login/euleros_openeuler_hce", value:TRUE );
    set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler", value:TRUE );
    set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler_hce", value:TRUE );
    release = ssh_cmd( socket:sock, cmd:"cat /etc/openEuler-release", return_errors:FALSE );
    if( release )
      set_kb_item( name:"policy/ssh/login/os-release", value:release );
  }

  # Huawei Cloud EulerOS keys for compliance development
  if( rls =~ 'NAME="Huawei Cloud EulerOS"' ) {
    set_kb_item( name:"policy/ssh/login/hce", value:TRUE );
    set_kb_item( name:"policy/ssh/login/openeuler_hce", value:TRUE );
    set_kb_item( name:"policy/ssh/login/euleros_openeuler_hce", value:TRUE );
    set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler_hce", value:TRUE );
    release = ssh_cmd( socket:sock, cmd:"cat /etc/hce-release", return_errors:FALSE );
    if( release )
      set_kb_item( name:"policy/ssh/login/os-release", value:release );
  }
}

exit( 0 );
