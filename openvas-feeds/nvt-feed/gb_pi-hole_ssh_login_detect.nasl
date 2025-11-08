# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155718");
  script_version("2025-11-07T15:43:15+0000");
  script_tag(name:"last_modification", value:"2025-11-07 15:43:15 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-07 09:09:46 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Pi-hole Ad-Blocker Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Pi-hole Ad-Blocker.");

  exit(0);
}

include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_bin(prog_name: "pihole", sock: soc);

foreach bin (paths) {
  bin = chomp(bin);
  if (!bin)
    continue;

  res = ssh_cmd(socket: soc, cmd: bin + " -v");

  # Core version is v6.2.2 (Latest: v6.2.2)
  # Web version is v6.3 (Latest: v6.3)
  # FTL version is v6.3.3 (Latest: v6.3.3)
  #
  # Pi-hole version is v5.12 (Latest: v5.12)
  # AdminLTE version is v5.14.2 (Latest: v5.14.2)
  # FTL version is v5.17 (Latest: v5.17)
  if ("Core version" >!< res && "Pi-hole version" >!< res)
    continue;

  pihole_version = "unknown";
  web_version = "unknnown";
  ftl_version = "unknown";

  set_kb_item(name: "pi-hole/detected", value: TRUE);
  set_kb_item(name: "pi-hole/ssh-login/detected", value: TRUE);
  set_kb_item(name: "pi-hole/ssh-login/port", value: port);
  set_kb_item(name: "pi-hole/ssh-login/" + port + "/location", value: bin);
  set_kb_item(name: "pi-hole/ssh-login/" + port + "/concluded", value: chomp(res));

  pihole_vers = eregmatch(pattern: "(Core|Pi-hole) version is v([0-9.]+)", string: res);
  if (!isnull(pihole_vers[2]))
    pihole_version = pihole_vers[2];

  web_vers = eregmatch(pattern: "(Web|AdminLTE) version is v([0-9.]+)", string: res);
  if (!isnull(web_vers[2]))
    web_version = web_vers[2];

  ftl_vers = eregmatch(pattern: "FTL version is v([0-9.]+)", string: res);
  if (!isnull(ftl_vers[1]))
    ftl_version = ftl_vers[1];

  set_kb_item(name: "pi-hole/ssh-login/" + port + "/pihole_version", value: pihole_version);
  set_kb_item(name: "pi-hole/ssh-login/" + port + "/web_version", value: web_version);
  set_kb_item(name: "pi-hole/ssh-login/" + port + "/ftl_version", value: ftl_version);
}

exit(0);
