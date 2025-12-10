# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155942");
  script_version("2025-12-09T05:47:47+0000");
  script_tag(name:"last_modification", value:"2025-12-09 05:47:47 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-08 05:31:33 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Firebird SQL Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("firebird_detect.nasl",
                      "gb_firebird_smb_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_firebird_ssh_login_detect.nasl");
  script_mandatory_keys("firebird/sql/detected");

  script_tag(name:"summary", value:"Consolidation of Firebird SQL detections.");

  script_xref(name:"URL", value:"https://www.firebirdsql.org/");

  exit(0);
}

if (!get_kb_item("firebird/sql/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("smb-login", "ssh-login")) {
  version_list = get_kb_list("firebird/sql/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:firebirdsql:firebird:");
if (!cpe)
  cpe = "cpe:/a:firebirdsql:firebird";

if (service_ports = get_kb_list("firebird/sql/gds_db/port")) {
  foreach port (service_ports) {
    extra += "Remote Detection on port " + port + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "gds_db");
  }
}

if (!isnull(concl = get_kb_item("firebird/sql/smb-login/0/concluded"))) {
  extra += 'Local Detection over SMB:\n';

  loc = get_kb_item("firebird/sql/smb-login/0/location");
  extra +="  Location:      " + loc + '\n';

  extra += '  Concludded from:\n' + concl + '\n';

  register_product(cpe: cpe, location: loc, port: 0, service: "smb-login");
}

if (ssh_login_ports = get_kb_list("firebird/sql/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "Local Detection via SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("firebird/sql/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    loc = get_kb_item("firebird/sql/ssh-login/" + port + "/location");
    if (loc)
      extra += "  Concluded from version/product identification location: " + loc + '\n';

    register_product(cpe: cpe, location: loc, port: 0, service: "ssh-login");
  }
}

report = build_detection_report(app: "Firebird SQL", version: detected_version, cpe: cpe, install: location);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
