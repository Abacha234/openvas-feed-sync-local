# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155729");
  script_version("2025-11-11T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-11 05:40:18 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-10 08:18:37 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pi-hole Ad-Blocker Detection (DNS)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_dnsmasq_consolidation.nasl");
  script_mandatory_keys("thekelleys/dnsmasq/detected");

  script_tag(name:"summary", value:"DNS (TCP and UDP) based detection of the Pi-hole Ad-Blocker.");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

function getVersion(port, proto) {
  local_var port, proto;
  local_var pihole_version, web_version, ftl_version, query;
  local_var raw_data_init, soc, raw_data, len;
  local_var res, vers;

  pihole_version = "unknown";
  web_version = "unknown";
  ftl_version = "unknown";

  query = "version.FTL";

  raw_data_init = raw_string(0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07);

  if (proto == "udp") {
    if (!soc = open_sock_udp(port))
      return;

    raw_data = raw_data_init;
  } else if (proto == "tcp") {
    if (!soc = open_sock_tcp(port))
      return;

    len = strlen(query) + 18;
    raw_data = raw_string(0x00, len) + raw_data_init;
  } else {
    return;
  }

  # nb: Dots need to be substituted with 0x03 instead of 0x04 as in other version queries
  query = str_replace(string: query, find: ".", replace: raw_string(0x03));
  raw_data = raw_data + query;
  raw_data = raw_data + raw_string(0x00, 0x00, 0x10, 0x00, 0x03);

  send(socket: soc, data: raw_data);
  res = recv(socket: soc, length: 512);
  close(soc);

  if (res) {
    vers = eregmatch(pattern: "v([0-9]+\.[0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      ftl_version = vers[1];
      set_kb_item(name: "pi-hole/dns/" + port + "/" + proto + "/ftl_concluded",
                  value: bin2string(ddata: res, noprint_replacement: " "));
    }
  }

  set_kb_item(name: "pi-hole/detected", value: TRUE);
  set_kb_item(name: "pi-hole/dns/detected", value: TRUE);
  set_kb_item(name: "pi-hole/dns/port", value: port);
  set_kb_item(name: "pi-hole/dns/" + port + "/proto", value: proto);
  set_kb_item(name: "pi-hole/dns/" + port + "/" + proto + "/pihole_version", value: pihole_version);
  set_kb_item(name: "pi-hole/dns/" + port + "/" + proto + "/web_version", value: web_version);
  set_kb_item(name: "pi-hole/dns/" + port + "/" + proto + "/ftl_version", value: ftl_version);
}

udp_ports = get_kb_list("DNS/udp/version_request");
foreach port (udp_ports) {
  data = get_kb_item("DNS/udp/version_request/" + port);
  if (!data || "dnsmasq-pi-hole" >!< tolower(data))
    continue;

  getVersion(port: port, proto: "udp");
}

tcp_ports = get_kb_list("DNS/tcp/version_request");
foreach port (tcp_ports) {
  data = get_kb_item("DNS/tcp/version_request/" + port);
  if (!data || "dnsmasq-pi-hole" >!< tolower(data))
    continue;

  getVersion(port: port, proto: "tcp");
}

exit(0);
