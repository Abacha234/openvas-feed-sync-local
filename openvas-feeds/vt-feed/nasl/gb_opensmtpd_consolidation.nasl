# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155745");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-11 07:51:02 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenSMTPD Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_opensmtpd_smtp_detect.nasl",
                      "gb_opensmtpd_ssh_login_detect.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"Consolidation of OpenSMTPD detections.");

  script_xref(name:"URL", value:"https://www.opensmtpd.org/");

  exit(0);
}

if (!get_kb_item("opensmtpd/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

# nb: Currently only via SSH login extracted
foreach source (make_list("ssh-login")) {
  version_list = get_kb_list("opensmtpd/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)(p[0-9]+)?", base: "cpe:/a:openbsd:opensmtpd:");
if (!cpe)
  cpe = "cpe:/a:openbsd:opensmtpd";

os_register_and_report(os: "Linux / Unix", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "OpenSMTPD Detection Consolidation");

if (smtp_ports = get_kb_list("opensmtpd/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("opensmtpd/smtp/" + port + "/concluded");
    if (concluded)
      extra += "  SMTP banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

if (ssh_login_ports = get_kb_list("opensmtpd/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login on port " + port + '/tcp\n';

    loc = get_kb_item("opensmtpd/ssh-login/" + port + "/location");
    if (loc)
      extra += "  Concluded from version/product identification location: " + loc + '\n';
    else
      loc = location;

    concluded = get_kb_item("opensmtpd/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: loc, port: 0, service: "ssh-login");
  }
}

report = build_detection_report(app: "OpenSMTPD", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
