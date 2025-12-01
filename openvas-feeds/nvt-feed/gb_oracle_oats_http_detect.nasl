# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809730");
  script_version("2025-11-14T15:41:06+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-11-14 15:41:06 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2016-11-25 10:47:18 +0530 (Fri, 25 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle Application Testing Suite Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Oracle Application Testing Suite.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8088);

version = "unknown";
location = "/";
conclUrl = "";

check_urls = make_list( "/olt/Login.do", "/otm/logon.do" );

foreach url ( check_urls ) {

  res = http_get_cache( port: port, item: url );

  if( res && ">Oracle Application Testing Suite Service Home Page<" >< res && "Login<" >< res ) {

    vers = eregmatch( pattern:"Version:&nbsp;([0-9.]+)( build ([0-9.]+))?", string:res );

    concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );

    if( vers[1] && vers[2] ) {
      concl = vers[1] + ' build ' + vers[3];
      version = vers[1];
      set_kb_item( name:"Oracle/Application/Testing/Suite/build", value:vers[3] );
    }
    else if( vers[1] ) {
      version = vers[1];
    }
    else {
      version = "unknown";
    }
    if( ver = eregmatch( pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)", string: version ) )
      version = ver[0];

    set_kb_item( name:"oracle/application_testing_suite/detected", value:TRUE );
    set_kb_item( name:"oracle/application_testing_suite/http/detected", value:TRUE );

    set_kb_item( name:"oracle/application_testing_suite/http/" + port + "/installs",
                 value: port + "#---#/#---#" + version + "#---#" + concl + "#---#" + concUrl );

    exit( 0 );
  }
}

exit( 0 );
