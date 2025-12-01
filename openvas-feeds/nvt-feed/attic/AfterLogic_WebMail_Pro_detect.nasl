# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100313");
  script_version("2025-11-27T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-11-27 05:40:40 +0000 (Thu, 27 Nov 2025)");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AfterLogic WebMail Pro Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");

  script_tag(name:"summary", value:"This host is running AfterLogic WebMail Pro, a Webmail
  front-end for your existing POP3/IMAP mail server.

  This VT has been deprecated and merged into the VT 'AfterLogic Aurora / WebMail Detection (HTTP)'
  (OID: 1.3.6.1.4.1.25623.1.0.140381).");

  script_xref(name:"URL", value:"http://www.afterlogic.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
