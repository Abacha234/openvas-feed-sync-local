# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144580");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-09-15 09:00:27 +0000 (Tue, 15 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM / Lotus Domino Detection (POP3)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("popserver_detect.nasl");
  script_mandatory_keys("pop3/hcl/domino/detected");

  script_tag(name:"summary", value:"POP3 based detection of HCL Domino (formerly Lotus/IBM
  Domino).");

  exit(0);
}

include("pop3_func.inc");
include("port_service_func.inc");

port = pop3_get_port(default: 110);

banner = pop3_get_banner(port: port);

if (banner && banner =~ "(HCL|Lotus|IBM) Notes POP3 Server") {
  set_kb_item(name: "hcl/domino/detected", value: TRUE);
  set_kb_item(name: "hcl/domino/pop3/port", value: port);
  set_kb_item(name: "hcl/domino/pop3/" + port + "/concluded", value: banner);

  version = "unknown";

  # OK HCL Notes POP3 server version Release 11.0.1 ready on Domino/SitiTarghe/IT.
  # OK IBM Notes POP3 server version Release 9.0.1FP10 HF383 ready on Domino/Aurora.
  # OK Lotus Notes POP3 server version Release 8.5.2 ready on domino/afp.
  vers = eregmatch(pattern: "Release ([0-9A-Z.]+[ ]?(HF[0-9]+)?)", string: banner);
  if (!isnull(vers[1])) {
    version = chomp(vers[1]);
    version = str_replace(string: version, find: "FP", replace: ".");
    version = ereg_replace(string: version, pattern: "( )?HF", replace: ".HF");
  }

  set_kb_item(name: "hcl/domino/pop3/" + port + "/version", value: version);
}

exit(0);
