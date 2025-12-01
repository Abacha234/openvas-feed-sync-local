# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107395");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"creation_date", value:"2018-12-03 10:17:14 +0100 (Mon, 03 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Schneider Electric Software Update Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"This detection has been deprecated and replaced by the detection
  'Schneider Electric Software Update Detection (Windows SMB Login, WSC)'
  (OID: 1.3.6.1.4.1.25623.1.0.125480).

  SMB login-based detection of Schneider Electric Software Update.");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
