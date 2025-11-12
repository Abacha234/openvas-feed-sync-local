# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief This OS detection retrieves all release information it needs itself to detect Oracle.
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

function detect_oracle(sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info) {

  if (is_pfsense)
    return _unknown_os_info;

  # nb: We're using /etc/oracle-release because /etc/redhat-release exists but includes e.g. the
  # following:
  #
  # Red Hat Enterprise Linux Server release 5.11 (Tikanga)
  #
  # Also note that in an early version of this check "rpm -qf /etc/redhat-release" was used but that
  # wasn't working on Oracle Linux 5 because it has the following:
  #
  # enterprise-release-5-11.0.3
  #
  # while newer Oracle Linux releases have:
  #
  # oraclelinux-release-6Server-10.0.2.x86_64
  #
  cmd = "cat /etc/oracle-release";

  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += cmd + ": " + rls + '\n\n';

  if( rls =~ "Oracle Linux ([^ ]+ )?release" ) {

    oskey = "OracleLinux";
    cpe = "cpe:/o:oracle:linux";
    os = "Oracle Linux";
    concluded  = '\n  Used command: ' + cmd;
    concluded += '\n  Response:     ' + rls;

    set_kb_item( name:"ssh/login/oracle_linux", value:TRUE );

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
    if( buf ) {
      if( ! register_rpms( buf:";" + buf ) )
        error = buf;

      buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
      if( buf ) {
        if( ! register_rpms( buf:buf ) )
          error = buf;
        else
          pkg_list = buf;
      }
    }

    vers = eregmatch( pattern:"Oracle Linux ([^ ]+ )?release ([0-9]+)([0-9.]+)?", string:rls, icase:TRUE );
    if( vers[2] ) {

      version = vers[2];

      if( vers[3] )
        version += vers[3];

      cpe += ":" + version;

      # nb: Special handling as the Oracle / ELSA LSCs are using just the major release version in
      # their OS key checks (e.g. OracleLinux7). This applies to Notus as well (e.g. "Oracle Linux 8")
      oskey += vers[2];
      oskey_notus = os + " " + vers[2];

      if( ! register_notus( os_release:oskey_notus, pkg_list:pkg_list, rpms:TRUE ) )
        error = pkg_list;

      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version, rpm_access_error:error ) );
      os_register_and_report( os:os, version:version, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    } else {
      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
      os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }

    set_kb_item( name:"ssh/login/release", value:oskey );

    exit( 0 );
  }

}
