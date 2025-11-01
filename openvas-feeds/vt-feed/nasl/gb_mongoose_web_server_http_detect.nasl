# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813630");
  script_version("2025-10-03T05:38:37+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-10-03 05:38:37 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"creation_date", value:"2018-07-09 14:45:19 +0530 (Mon, 09 Jul 2018)");
  script_name("Cesanta Mongoose Web Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Mongoose/banner");

  script_xref(name:"URL", value:"https://cesanta.com/");
  script_xref(name:"URL", value:"https://mongoose.ws/");

  script_tag(name:"summary", value:"HTTP based detection of Cesanta Mongoose Web Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if(!banner = http_get_remote_headers(port:port))
  exit(0);

# Server: Mongoose/6.11
# Server: Mongoose
# Server: Mongoose/6.18
# Server: Mongoose/6.5
# Server: Mongoose/6.4
if(!concl = egrep(string:banner, pattern:"^Server\s*:\s*Mongoose", icase:TRUE))
  exit(0);

concl = chomp(concl);

version = "unknown";
install = port + "/tcp";

vers = eregmatch(string:concl, pattern:"Server\s*:\s*Mongoose/([0-9.]+)", icase:TRUE);
if(vers[1])
  version = vers[1];

set_kb_item(name:"cesanta/mongoose/detected", value:TRUE);
set_kb_item(name:"cesanta/mongoose/http/detected", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:cesanta:mongoose:");
if(!cpe)
  cpe = "cpe:/a:cesanta:mongoose";

register_product(cpe:cpe, port:port, location:install, service:"www");

log_message(data:build_detection_report(app:"Cesanta Mongoose Web Server",
                                        version:version,
                                        install:install,
                                        cpe:cpe,
                                        concluded:concl),
            port:port);

exit(0);
