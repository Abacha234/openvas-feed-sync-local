# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112137");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-11-23 10:50:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OPENVAS SCAN / Greenbone Enterprise Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of OPENVAS SCAN / Greenbone Enterprise
  Appliance (GEA) / Greenbone Security Manager (GSM) / Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

# nb: On GOS 5.0+ the URL is just "/login" but GSA has a "catchall" login page so this URL works as well
url = "/login/login.html";
buf = http_get_cache( item:url, port:port );
if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

# nb: GOS 4.3 and below
if( ( concl = eregmatch( string:buf, pattern:"Greenbone OS", icase:FALSE ) ) &&
    "<title>Greenbone Security Assistant" >< buf ) {
  found = TRUE;
  concluded = "    " + concl[0];
}

# nb: GOS 5.0+
#
# "title">Greenbone Security Manager</span>
# <title>Greenbone Security Manager</title>
#
if( concl = eregmatch( string:buf, pattern:'("title">Greenbone Security Manager</span>|<title>Greenbone Security Manager</title>)', icase:FALSE ) ) {
  found = TRUE;
  concluded = "    " + concl[0];
}

# nb: GOS 22.04+
#
# <title>Greenbone Enterprise Appliance</title>
#
if( concl = eregmatch( string:buf, pattern:"<title>Greenbone Enterprise Appliance</title>", icase:FALSE ) ) {
  found = TRUE;
  concluded = "    " + concl[0];
}

# And another renaming in late 2025 (with GOS 24.10.06):
# - https://forum.greenbone.net/t/greenbone-os-24-10-6-released/21801
# - https://www.greenbone.net/en/blog/openvas-the-new-name-for-proven-greenbone-security/
#
# e.g.
#
# <title>OPENVAS SCAN</title>
#
# And either (seems to depend on the version):
#
# <link rel="modulepreload" crossorigin href="/assets/opensight-ui-<redacted>.js">
# <link rel="stylesheet" crossorigin href="/assets/opensight-ui-<redacted>.css">
#
# or:
#
# <link rel="modulepreload" crossorigin href="/assets/greenbone-ui-<redacted>.js">
# <link rel="stylesheet" crossorigin href="/assets/greenbone-ui-<redacted>.css">
#
if( ( concl = eregmatch( string:buf, pattern:"<title>OPENVAS SCAN</title>", icase:FALSE ) ) &&
    buf =~ "/(greenbone|opensight)-ui-"
  ) {
  found = TRUE;
  concluded = "  " + concl[0];
}

if( found ) {

  type = "unknown";
  version = "unknown";
  conclurl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/http/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/http/port", value:port );
  set_kb_item( name:"greenbone/gos/http/" + port + "/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is not
  # supporting these.
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );

  # <div class="gos_version">Greenbone OS 1.2.3</div>
  # <span class="version">Greenbone OS 1.2.3</span>
  # <span class="version">Version Greenbone OS 1.2.3</span>
  vers = eregmatch( string:buf, pattern:'<(div|span) class="(gos_)?version">(Version )?Greenbone OS ([^<]+)</(div|span)>', icase:FALSE );
  if( ! isnull( vers[4] ) ) {
    version = vers[4];
    concluded = vers[0];
  }

  # This is GOS 5.0+
  if( version == "unknown" ) {

    url2 = "/config.js";
    req = http_get( item:url2, port:port );
    buf2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # config = {
    #     vendorVersion: 'Greenbone OS 5.0.1',
    #     vendorLabel: 'gsm-one_label.svg',
    # }
    #
    # or:
    #
    # config = {
    #     vendorVersion: 'Greenbone OS 5.0.1',
    #     vendorLabel: 'gsm-600_label.svg',
    # }
    #
    # or:
    #
    # config = {
    #     *snip*
    #     manualUrl: '/manual',
    #     *snip*
    #     vendorVersion: 'Greenbone OS 24.10.6',
    #     vendorLabel: 'deca.svg',
    #     vendorTitle: 'OPENVAS SCAN',
    # }

    if( buf2 =~ "^HTTP/1\.[01] 200" && "Greenbone OS" >< buf2 ) {

      vers = eregmatch( string:buf2, pattern:"vendorVersion: 'Greenbone OS ([^']+)',", icase:FALSE );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];

        concluded = "    " + vers[0];

        # nb: See note about /login/login.html above, it is expected that this is getting
        # overwritten here
        conclurl = "    " + http_report_vuln_url( port:port, url:"/login", url_only:TRUE );
      }
    }
  }

  # e.g.:
  # <img src="/img/gsm-one_label.svg"></img>
  # <img src="/img/GSM_DEMO_logo_95x130.png" alt=""></td>
  # vendorLabel: 'gsm-one_label.svg',
  # vendorLabel: 'deca.svg',
  _type = eregmatch( string:buf, pattern:'<img src="/img/gsm-([^>]+)_label\\.svg"></img>', icase:FALSE );
  if( ! _type[1] ) {
    _type = eregmatch( string:buf, pattern:'<img src="/img/GSM_([^>]+)_logo_95x130\\.png" alt=""></td>', icase:FALSE );
  }

  if( ! _type[1] ) {
    _type = eregmatch( string:buf2, pattern:"vendorLabel: 'gsm-([^']+)_label\.svg',", icase:FALSE );
    if( _type[1] )
      conclurl += '\n    ' + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( ! _type[1] ) {
    _type = eregmatch( string:buf2, pattern:"vendorLabel: '([a-z0-9]+)\.svg',", icase:FALSE );
    if( _type[1] )
      conclurl += '\n    ' + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( _type[1] ) {
    # nb: Products are named uppercase
    type = toupper( _type[1] );
    concluded += '\n    ' + _type[0];
  }

  set_kb_item( name:"greenbone/gos/http/" + port + "/version", value:version );
  set_kb_item( name:"greenbone/gsm/http/" + port + "/type", value:type );
  set_kb_item( name:"greenbone/gos/http/" + port + "/concluded", value:concluded );
  set_kb_item( name:"greenbone/gos/http/" + port + "/concludedUrl", value:conclurl );
}

exit( 0 );
