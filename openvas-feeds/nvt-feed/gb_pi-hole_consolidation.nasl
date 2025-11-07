# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155703");
  script_version("2025-11-06T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-11-06 05:40:15 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-05 05:12:01 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pi-hole Ad-Blocker Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"Consolidation of Pi-hole Ad-Blocker detections.");

  script_xref(name:"URL", value:"https://pi-hole.net/");

  exit(0);
}

if (!get_kb_item("pi-hole/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_pihole_version = "unknown";
detected_web_version = "unknown";
detected_ftl_version = "unknown";
location = "/";

foreach source (make_list("http")) {
  pihole_version_list = get_kb_list("pi-hole/" + source + "/*/pihole_version");
  foreach version (pihole_version_list) {
    if (version != "unknown" && detected_pihole_version == "unknown") {
      detected_pihole_version = version;
      break;
    }
  }

  web_version_list = get_kb_list("pi-hole/" + source + "/*/web_version");
  foreach version (web_version_list) {
    if (version != "unknown" && detected_web_version == "unknown") {
      detected_web_version = version;
      break;
    }
  }

  ftl_version_list = get_kb_list("pi-hole/" + source + "/*/ftl_version");
  foreach version (ftl_version_list) {
    if (version != "unknown" && detected_ftl_version == "unknown") {
      detected_ftl_version = version;
      break;
    }
  }
}

# Runs only on Linux based OS like Debian, Ubuntu, Fedora etc.
os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key:"unixoide",
                       desc: "Pi-hole Ad-Blocker Detection Consolidation");

pihole_cpe = build_cpe(value: detected_pihole_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:pi-hole:");
if (!pihole_cpe)
  pihole_cpe = "cpe:/a:pi-hole:pi-hole";

# nb: The product was called "AdminLTE" previously and both are currently used in the NVD so we
# are registering both but only use the newer name in the reporting
web_cpe = build_cpe(value: detected_web_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:web_interface:");
adminlte_cpe = build_cpe(value: detected_web_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:adminlte:");
if (!web_cpe) {
  web_cpe = "cpe:/a:pi-hole:web_interface";
  adminlte_cpe = "cpe:/a:pi-hole:adminlte";
}

ftl_cpe = build_cpe(value: detected_ftl_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:ftldns:");
if (!ftl_cpe)
  ftl_cpe = "cpe:/a:pi-hole:ftldns";

if (http_ports = get_kb_list("pi-hole/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    pihole_concluded = get_kb_item("pi-hole/http/" + port + "/pihole_concluded");
    if (pihole_concluded)
      extra += "  Pi-Hole Core version concluded from:  " + pihole_concluded + '\n';

    web_concluded = get_kb_item("pi-hole/http/" + port + "/web_concluded");
    if (web_concluded)
      extra += "  Web Interface version concluded from: " + web_concluded + '\n';

    ftl_concluded = get_kb_item("pi-hole/http/" + port + "/ftl_concluded");
    if (ftl_concluded)
      extra += "  FTL DNS version concluded from:       " + ftl_concluded + '\n';

    conclUrl = get_kb_item("pi-hole/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    banner = get_kb_item("pi-hole/http/" + port + "/concludedBanner");
    if (banner)
      extra += "  Banner: " + banner + '\n';

    if (detected_pihole_version == "unknown" ||
        detected_web_version == "unknown" ||
        detected_ftl_version == "unknown") {
      error = get_kb_item("pi-hole/http/" + port + "/error");
    }

    register_product(cpe: pihole_cpe, location: location, port: port, service: "www");
    register_product(cpe: web_cpe, location: location, port: port, service: "www");
    register_product(cpe: adminlte_cpe, location: location, port: port, service: "www");
    register_product(cpe: ftl_cpe, location: location, port: port, service:"www");
  }
}

report  = build_detection_report(app: "Pi-hole", version: detected_pihole_version, install: location,
                                 cpe: pihole_cpe);
report += '\n\n';
report += build_detection_report(app: "Pi-hole Web Interface (Previously AdminLTE)",
                                 version: detected_web_version, install: location, cpe: web_cpe);
report += '\n\n';
report += build_detection_report(app: "Pi-hole FTL DNS", version: detected_ftl_version, install: location,
                                 cpe: ftl_cpe, extra: error);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
