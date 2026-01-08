# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156083");
  script_version("2026-01-07T05:47:44+0000");
  script_tag(name:"last_modification", value:"2026-01-07 05:47:44 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-06 03:41:26 +0000 (Tue, 06 Jan 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SmarterTools SmarterMail Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_smartermail_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_smartermail_imap_detect.nasl",
                        "gsf/gb_smartermail_pop3_detect.nasl",
                        "gsf/gb_smartermail_smtp_detect.nasl");
  script_mandatory_keys("smartertools/smartermail/detected");

  script_tag(name:"summary", value:"Consolidation of SmarterTools SmarterMail detections.");

  script_xref(name:"URL", value:"https://www.smartertools.com/smartermail/business-email-server");

  exit(0);
}

if (!get_kb_item("smartertools/smartermail/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

# nb: Only via HTTP or SMTP extractable
foreach source (make_list("http", "smtp")) {
  version_list = get_kb_list("smartertools/smartermail/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:smartertools:smartermail:");
if (!cpe)
  cpe = "cpe:/a:smartertools:smartermail";

report = build_detection_report(app: "SmarterTools SmarterMail", version: detected_version,
                                install: location, cpe: cpe);

if (http_ports = get_kb_list("smartertools/smartermail/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("smartertools/smartermail/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("smartertools/smartermail/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (smtp_ports = get_kb_list("smartertools/smartermail/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("smartertools/smartermail/smtp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from banner: " + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

if (pop3_ports = get_kb_list("smartertools/smartermail/pop3/port")) {
  foreach port (pop3_ports) {
    extra += "POP3 on port " + port + '/tcp\n';

    concluded = get_kb_item("smartertools/smartermail/pop3/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from banner: " + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

if (imap_ports = get_kb_list("smartertools/smartermail/imap/port")) {
  foreach port (imap_ports) {
    extra += "IMAP on port " + port + '/tcp\n';

    concluded = get_kb_item("smartertools/smartermail/imap/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from banner: " + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
