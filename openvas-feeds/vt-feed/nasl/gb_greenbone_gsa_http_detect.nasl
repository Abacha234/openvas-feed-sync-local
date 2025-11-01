# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103841");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"creation_date", value:"2013-11-29 14:30:41 +0100 (Fri, 29 Nov 2013)");
  script_name("Greenbone Security Assistant (GSA) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9392);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/greenbone/gsa");

  script_tag(name:"summary", value:"HTTP based detection of the Greenbone Security Assistant
  (GSA).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("cpe.inc");

port = http_get_port( default:9392 );

url = "/login/login.html";
buf = http_get_cache( item:url, port:port );

if( buf && buf =~ "^HTTP/1\.[01] 200" && '<form action="/omp" method="' >< buf &&
    ( concl = eregmatch( string:buf, pattern:"Greenbone Security Assistant", icase:FALSE ) ) ) {

  concluded = "  " + concl[0];
  conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  install  = "/";
  version  = "unknown";

  # <span class="version">Version 7.0.3</span>
  vers  = eregmatch( string:buf, pattern:'<span class="version">Version ([^<]+)</span>', icase:FALSE );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
  }

  set_kb_item( name:"greenbone/gsa/detected", value:TRUE );
  set_kb_item( name:"greenbone/gsa/http/detected", value:TRUE );
  set_kb_item( name:"greenbone/gsa/pre80/detected", value:TRUE );
  set_kb_item( name:"greenbone/gsa/pre80/http/detected", value:TRUE );

  # nb: for 2015/gb_gsa_http_default_credentials.nasl to be able to choose the auth endpoint
  set_kb_item( name:"greenbone/gsa/" + port + "/omp", value:TRUE );

  set_kb_item( name:"greenbone/gsa/" + port + "/version", value:version );
  set_kb_item( name:"openvas_gvm/framework_component/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is not
  # supporting these.
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );

  cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/a:greenbone:greenbone_security_assistant:" );
  if( ! cpe )
    cpe = "cpe:/a:greenbone:greenbone_security_assistant";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Greenbone Security Assistant (GSA) Detection (HTTP)", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Greenbone Security Assistant (GSA)",
                                            version:version,
                                            install:install,
                                            concluded:concluded,
                                            concludedUrl:conclUrl,
                                            cpe:cpe ),
               port:port );
  exit( 0 );
}

url = "/login";
buf = http_get_cache( item:url, port:port );
if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

# nb: Plain GSA installation from sources before the renaming mentioned below
# <title>Greenbone Security Assistant</title>
#
# nb: On GOS <= 21.04
# <title>Greenbone Security Manager</title>
#
# nb: On GOS >= 22.04
# <title>Greenbone Enterprise Appliance</title>
if( concl = eregmatch( string:buf, pattern:"<title>Greenbone (Security Assistant|Security Manager|Enterprise Appliance)</title>", icase:FALSE ) ) {
  found = TRUE;
  concluded = "  " + concl[0];
}

# And another renaming in late 2025 (with GOS 24.10.06):
# - https://forum.greenbone.net/t/greenbone-os-24-10-6-released/21801
# - https://www.greenbone.net/en/blog/openvas-the-new-name-for-proven-greenbone-security/
#
# On a source installation:
#
# <title>OPENVAS</title>
#
# and on the OPENVAS SCAN appliance:
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
if( ( concl = eregmatch( string:buf, pattern:"<title>OPENVAS( SCAN)?</title>", icase:FALSE ) ) &&
    buf =~ "/(greenbone|opensight)-ui-"
  ) {
  found = TRUE;
  concluded = "  " + concl[0];
}

if( found ) {

  conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  install  = "/";
  version  = "unknown";

  set_kb_item( name:"greenbone/gsa/detected", value:TRUE );
  set_kb_item( name:"greenbone/gsa/http/detected", value:TRUE );
  set_kb_item( name:"greenbone/gsa/80plus/detected", value:TRUE );
  set_kb_item( name:"greenbone/gsa/80plus/http/detected", value:TRUE );

  # nb: for 2015/gb_gsa_http_default_credentials.nasl to be able to choose the auth endpoint
  set_kb_item( name:"greenbone/gsa/" + port + "/gmp", value:TRUE );

  set_kb_item( name:"greenbone/gsa/" + port + "/version", value:version );
  set_kb_item( name:"openvas_gvm/framework_component/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service doesn't support these
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );

  cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/a:greenbone:greenbone_security_assistant:" );
  if( ! cpe )
    cpe = "cpe:/a:greenbone:greenbone_security_assistant";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Greenbone Security Assistant (GSA) Detection (HTTP)", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Greenbone Security Assistant (GSA)",
                                            version:version,
                                            install:install,
                                            concluded:concluded,
                                            concludedUrl:conclUrl,
                                            cpe:cpe ),
               port:port );
}

exit( 0 );
