# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144577");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-09-15 09:00:27 +0000 (Tue, 15 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM / Lotus Domino Detection (IMAP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl");
  script_mandatory_keys("imap/hcl/domino/detected");

  script_tag(name:"summary", value:"IMAP based detection of HCL Domino (formerly Lotus/IBM
  Domino).");

  exit(0);
}

include("imap_func.inc");
include("port_service_func.inc");

port = imap_get_port(default: 143);

banner = imap_get_banner(port: port);

if (banner && "Domino IMAP4 Server" >< banner) {
  set_kb_item(name: "hcl/domino/detected", value: TRUE);
  set_kb_item(name: "hcl/domino/imap/port", value: port);
  set_kb_item(name: "hcl/domino/imap/" + port + "/concluded", value: banner);

  version = "unknown";

  # OK Domino IMAP4 Server Release 9.0.1FP10 HF66 ready Tue, 15 Sep 2020 10:13:05 +0200
  # OK Domino IMAP4 Server Release 8.5.3 ready Tue, 15 Sep 2020 01:59:18 -0600
  # OK Domino IMAP4 Server Release 8.5 HF1 ready Tue, 15 Sep 2020 11:49:54 +0300
  vers = eregmatch(pattern: "Domino IMAP4 Server Release ([0-9A-Z.]+[ ]?(HF[0-9]+)?)", string: banner);
  if (!isnull(vers[1])) {
    version = chomp(vers[1]);
    version = str_replace(string: version, find: "FP", replace: ".");
    version = ereg_replace(string: version, pattern: "( )?HF", replace: ".HF");
  }

  set_kb_item(name: "hcl/domino/imap/" + port + "/version", value: version);
}

exit(0);
