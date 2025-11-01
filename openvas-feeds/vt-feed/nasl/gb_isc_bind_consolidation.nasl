# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145294");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2021-02-02 04:14:12 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ISC BIND Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of ISC BIND detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("isc_bind_dns_detect.nasl", "gb_isc_bind_ssh_login_detect.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"https://www.isc.org/bind/");

  exit(0);
}

if (!get_kb_item("isc/bind/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source (make_list("ssh-login", "domain")) {
  install_list = get_kb_list("isc/bind/" + source + "/*/installs");
  if (!install_list)
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort(install_list);

  foreach install (install_list) {
    infos = split(install, sep: "#---#", keep: FALSE);
    if (max_index(infos) < 5)
      continue; # Something went wrong and not all required infos are there...

    port    = infos[0];
    install = infos[1];
    version = infos[2];
    update  = infos[3];
    proto   = infos[4];
    concl   = infos[5];
    if (!isnull(concl))
      concluded = concl;

    cpe = build_cpe(value: tolower(version), exp: "^([0-9.]+)", base: "cpe:/a:isc:bind:");
    if (!cpe)
      cpe = "cpe:/a:isc:bind";
    else {
      if (update) {
        version += "-" + update;
        # nb: NVD CPE database is using "r11_w1" for "R11-W1" or "p2_w1" for "P2-W1".
        update = ereg_replace(string: update, pattern: "-", replace: "_");
        cpe += ":" + tolower(update);
      }
    }

    register_product(cpe: cpe, location: install, port: port, service: source, proto: proto);

    if (report)
      report += '\n\n';
    report += build_detection_report(app: "ISC BIND", version: version, install: install, cpe: cpe,
                                     concluded: concluded);
  }
}

if (report)
  log_message(port: 0, data: report);

exit(0);
