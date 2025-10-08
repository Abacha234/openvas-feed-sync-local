# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105614");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2016-04-21 10:11:13 +0200 (Thu, 21 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Prime Infrastructure (PIS) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_pis_ssh_login_detect.nasl",
                      "gb_cisco_pis_http_detect.nasl");
  script_mandatory_keys("cisco/pis/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco Prime Infrastructure (PIS)detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/cloud-systems-management/prime-infrastructure/series.html");

  exit(0);
}

if (!get_kb_item("cisco/pis/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_build = "";
detected_patches = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("cisco/pis/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  patches_list = get_kb_list("cisco/pis/" + source + "/*/installed_patches");
  foreach patches (patches_list) {
    if (patches != "unknown" && detected_patches == "unknown") {
      detected_patches = patches;
      set_kb_item(name: "cisco/pis/installed_patches", value: detected_patches);
      installed_patches = '  Installed Patches:\n' + detected_patches;
      break;
    }
  }

  build_list = get_kb_list("cisco/pis/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "") {
      detected_build = build;
      set_kb_item(name: "cisco/pis/build", value: detected_build);
      break;
    }
  }
}

os_register_and_report(os: "Cisco Application Deployment Engine OS",
                       cpe: "cpe:/o:cisco:application_deployment_engine", runs_key: "unixoide",
                       desc: "Cisco Prime Infrastructure (PIS) Detection Consolidation");

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:prime_infrastructure:");
if (!cpe)
  cpe = "cpe:/a:cisco:prime_infrastructure";

if (http_ports = get_kb_list("cisco/pis/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/pis/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("cisco/pis/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("cisco/pis/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/pis/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + chomp(concluded) + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Cisco Prime Infrastructure (PIS)", version: detected_version,
                                build: detected_build, install: location, cpe: cpe, extra: installed_patches);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
