# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief This OS detection retrieves all release information it needs itself to detect HCE.
#        On a successful detection the relevant info is set into the KB key and reported via
#        @ref log_message() and @ref os_register_and_report().
#
# @note It should be included in the appropriate section of gather-package-list.nasl with
#       `include("<this_files_name>")`.
#
# @note The OS detection method should be called also at the appropriate section in
#       gather-package-list.nasl.
#
# @param sock             The opened socket for the connection to the remote SSH service.
# @param port             The port for the connection to the remote SSH service.
# @param SCRIPT_DESC      The script name of the "caller" (defined within the caller itself)
# @param is_pfsense       Should be set to TRUE if the target is running pfSense as this requires
#                         some special handling.
# @param _unknown_os_info The "_unknown_os_info" variable filled in by the caller
#
# @return This function is either exiting directly on a successful detection or is returning the
#         info passed via the _unknown_os_info variable.

function detect_hce(sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info) {

  # nb: function parameters
  local_var sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info;

  # nb: variables from function body
  local_var cmd, rls, notusoskey, buf;

  if (is_pfsense)
    return _unknown_os_info;

  cmd = "cat /etc/os-release";
  rls = ssh_cmd(socket:sock, cmd:cmd, return_errors:FALSE);

  if( "Huawei Cloud EulerOS" >< rls ) {
    vers = eregmatch( pattern:'VERSION_ID="([0-9.]+)"', string:rls, icase:TRUE );
    if( vers[1] ) {
      notusoskey = "HCE" + " " + vers[1];

      cpe = "cpe:/o:huawei:hce" + ":" + vers[1];
      set_kb_item( name:"ssh/login/hce", value:TRUE );

      # Huawei Cloud EulerOS keys for compliance development
      set_kb_item( name:"policy/ssh/login/hce", value:TRUE );
      set_kb_item( name:"policy/ssh/login/openeuler_hce", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_openeuler_hce", value:TRUE );
      set_kb_item( name:"policy/ssh/login/euleros_eulerosvirtual_openeuler_hce", value:TRUE );
      os = "HCE";

      buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
      if( buf ) {
        if( ! register_notus( os_release:notusoskey, pkg_list:buf, rpms:TRUE ) )
          error = buf;
      }

      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + vers[1], rpm_access_error:error ) );
      os_register_and_report( os:os, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    }

  exit( 0 );
  }
}
