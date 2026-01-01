# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140787");
  script_version("2025-12-12T15:41:28+0000");
  script_tag(name:"last_modification", value:"2025-12-12 15:41:28 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"creation_date", value:"2018-02-20 12:32:03 +0700 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AlgoSec Detection");

  script_tag(name:"summary", value:"Detection of AlgoSec Security Management Solution.

  The script sends a connection request to the server and attempts to detect AlgoSec and to extract
  its version.


  This VT has been deprecated and merged into the VT 'AlgoSec Security Management Suite Detection
  (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.155975).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");

  script_xref(name:"URL", value:"https://www.algosec.com/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
