# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119218");
  script_version("2025-10-31T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-10-31 15:42:05 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-31 09:34:02 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Windows Server Update Services (WSUS) Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("microsoft_wsus_admin_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_microsoft_wsus_http_detect.nasl");
  script_mandatory_keys("microsoft/wsus/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus");
  # nb: No "en-us" link available but the page below is in english so fine for now...
  script_xref(name:"URL", value:"https://learn.microsoft.com/de-de/security-updates/windowsupdateservices/18127428");

  script_tag(name:"summary", value:"Consolidation of Microsoft Windows Server Update Services (WSUS)
  detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( ! get_kb_item( "microsoft/wsus/detected" ) )
  exit( 0 );

include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
cpe = "cpe:/a:microsoft:windows_server_update_services";

if( http_admin_ports = get_kb_list( "microsoft/wsus/http-admin/port" ) ) {
  foreach port( http_admin_ports ) {
    extra += 'HTTP(s) administration console on port ' + port + '/tcp\n';

    concluded = get_kb_item( "microsoft/wsus/http-admin/" + port + "/concluded" );
    concludedUrl = get_kb_item( "microsoft/wsus/http-admin/" + port + "/concludedUrl" );

    if( concluded )
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    if( concludedUrl )
      extra += '  Concluded from version/product identification location:\n' + concludedUrl + '\n';

    register_product( cpe:cpe, location:"/WsusAdmin", port:port, service:"www" );
  }
}

if( http_client_ports = get_kb_list( "microsoft/wsus/http-client/port" ) ) {
  foreach port( http_client_ports ) {
    extra += 'HTTP(s) client interface on port ' + port + '/tcp\n';

    concluded = get_kb_item( "microsoft/wsus/http-client/" + port + "/concluded" );
    concludedUrl = get_kb_item( "microsoft/wsus/http-client/" + port + "/concludedUrl" );

    if( concluded )
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    if( concludedUrl )
      extra += '  Concluded from version/product identification location:\n' + concludedUrl + '\n';

    register_product( cpe:cpe, location:"/", port:port, service:"www" );
  }
}

os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", desc:"Microsoft Windows Server Update Services (WSUS) Consolidation", runs_key:"windows" );

report = build_detection_report( app:"Microsoft Windows Server Update Services (WSUS)", version:detected_version, install:"/", cpe:cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
