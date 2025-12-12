# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107507");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"creation_date", value:"2019-02-04 12:32:25 +0100 (Mon, 04 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ABB Automation Builder Installation Manager Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"SMB login-based detection of ABB Automation Builder Installation
  Manager.

  This VT has been deprecated and replaced by the VT 'ABB Automation Builder Installation Manager
  Detection (Windows SMB Login, WSC)' (OID: 1.3.6.1.4.1.25623.1.0.136714).");

  script_xref(name:"URL", value:"https://new.abb.com/plc/automationbuilder/platform");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
