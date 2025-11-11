# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief This OS detection retrieves all release information it needs itself to detect Amazon.
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

function detect_amazon(sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info) {

  if (is_pfsense)
    return _unknown_os_info;

  rls = ssh_cmd( socket:sock, cmd:"cat /etc/system-release", return_errors:FALSE );
  if( strlen( rls ) )
    _unknown_os_info += '/etc/system-release: ' + rls + '\n\n';

  # NOTE: /etc/os-release can also be used.
  if( "Amazon Linux" >< rls ) {

    os_key = "Amazon Linux";
    cpe_key = "cpe:/o:amazon:linux";
    kb_item_release = "AMAZON";

    # nb: Standardized login key for Amazon Linux
    set_kb_item( name:"ssh/login/amazon_linux", value:TRUE );

    if( "Amazon Linux AMI release" >< rls ) {
      set_kb_item( name:"ssh/login/release", value:kb_item_release );

    } else {
      vers = eregmatch( pattern:"Amazon Linux release ([0-9]+)", string:rls, icase:TRUE );

      if( vers[1] ) {
        kb_item_release = "AMAZON" + vers[1];
        os_key += " " + vers[1];
        cpe_key += "_" + vers[1];

        set_kb_item( name:"ssh/login/release", value:kb_item_release );
      } else {
        # nb: In case, an unknown/unsupported format is detected
        os_key += " Unknown Release";
        cpe_key += "_unknown_release";
      }
    }

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
    if( buf ) {
      if( ! register_rpms( buf:";" + buf ) )
        error = buf;
    }

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_notus( os_release:os_key, pkg_list:buf, rpms:TRUE ) )
        error = buf;
    }

    log_message( port:port, data:create_lsc_os_detection_report( rpm_access_error:error, detect_text:os_key ) );
    os_register_and_report( os:os_key, cpe:cpe_key, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

    exit( 0 );
  }
}
