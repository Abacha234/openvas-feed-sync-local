# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155746");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-11 08:36:10 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("OpenSMTPD Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenSMTPD.");

  exit(0);
}

include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_bin(prog_name: "smtpd", sock: soc);

foreach bin (paths) {
  bin = chomp(bin);
  if (!bin)
    continue;

  # version: OpenSMTPD 6.8.0p2
  # version: OpenSMTPD 7.4.0-portable
  vers = ssh_get_bin_version(full_prog_name: bin, version_argv: "-h", ver_pattern: "OpenSMTPD ([0-9p.]+)",
                             sock: soc);
  if (!vers || !vers[0])
    continue;

  set_kb_item(name: "opensmtpd/detected", value: TRUE);
  set_kb_item(name: "opensmtpd/ssh-login/detected", value: TRUE);
  set_kb_item(name: "opensmtpd/ssh-login/port", value: port);
  set_kb_item(name: "opensmtpd/ssh-login/" + port + "/version", value: vers[1]);
  set_kb_item(name: "opensmtpd/ssh-login/" + port + "/concluded", value: vers[2]);
  set_kb_item(name: "opensmtpd/ssh-login/" + port + "/location", value: bin);
}

exit(0);
