# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141772");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"creation_date", value:"2018-12-12 13:23:36 +0700 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation MicroLogix Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Rockwell Automation MicroLogix detections.

  This VT has been deprecated and replaced by the VT 'Rockwell Automation Hardware Detection
  Consolidation (OID: 1.3.6.1.4.1.25623.1.0.136503).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");

  script_xref(name:"URL", value:"http://ab.rockwellautomation.com/Programmable-Controllers/MicroLogix-Systems");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
