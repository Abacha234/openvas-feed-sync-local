# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief This OS detection retrieves all release information it needs itself to detect Slackware.
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

function detect_slackware(sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info) {

  if (is_pfsense)
    return _unknown_os_info;

  rls = ssh_cmd( socket:sock, cmd:"cat /etc/slackware-version", return_errors:FALSE );
  if( strlen( rls ) )
    _unknown_os_info += '/etc/slackware-version: ' + rls + '\n\n';

  if( "Slackware " >< rls ) {
    oskey = "SLK";
    oskey_notus = "Slackware";
    cpe = "cpe:/o:slackware:slackware_linux";
    set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"ls -1 /var/log/packages" );
    if( buf ) {
      set_kb_item( name:"ssh/login/slackpack", value:buf );
    }

    vers = eregmatch( pattern:"Slackware (([0-9]+)\.([0-9]+))(\+$)?", string:rls, icase:FALSE );

    if( vers[1] ) {
      # If the release ends in a "+", the host is running Slackware current.
      if( vers[4] ) {
        release = "current";
      } else {
        release = vers[1];
      }
      # Even if the release is current, the CPE will be for the latest major release
      cpe += ":" + vers[1];
      oskey += release;
      oskey_notus += " " + release;

      if( buf )
        register_notus( os_release:oskey_notus, pkg_list:buf, rpms:FALSE );

      log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Slackware " + release ) );
      os_register_and_report( os:"Slackware", version:release, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    } else {
      log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Slackware" ) );
      os_register_and_report( os:"Slackware", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    }

    set_kb_item( name:"ssh/login/release", value:oskey );

    exit( 0 );
  }
}
