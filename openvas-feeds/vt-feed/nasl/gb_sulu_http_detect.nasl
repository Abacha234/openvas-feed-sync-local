# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124594");
  script_version("2026-01-09T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-09 05:47:51 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"creation_date", value:"2025-12-01 08:14:14 +0100 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sulu Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("sulu/banner");

  script_tag(name:"summary", value:"HTTP based detection of Sulu.");

  script_xref(name:"URL", value:"https://sulu.io/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

# X-Generator: Sulu/1.7.0
# X-Generator: Sulu/2.5.10
# X-Generator: Sulu/2.6.12
if(concl = egrep(string: banner, pattern: "^([Xx]\-Generator\s*:\s*Sulu\/([0-9.]+))", icase: FALSE)) {

  concl = chomp(concl);
  concluded = "";
  concl_split = split(concl, keep:FALSE);
  foreach split(concl_split) {
    if(concluded)
      concluded += '\n';
    concluded += "  " + split;
  }

  version = "unknown";
  location = "/";

  vers = eregmatch(string: banner, pattern: "[Xx]\-Generator\s*:\s*(Sulu\/([0-9.]+))");
  if(vers[2])
    version = vers[2];

  set_kb_item(name: "sulu/detected", value: TRUE);
  set_kb_item(name: "sulu/http/detected", value: TRUE);
  set_kb_item(name: "sulu/http/port", value: port);

  cpe = build_cpe(value: version, exp: "([0-9.+]+)", base: "cpe:/a:sulu:sulu:");
  if(!cpe)
    cpe = "cpe:/a:sulu:sulu";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Sulu",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: concluded),
              port: port);
}

exit(0);
