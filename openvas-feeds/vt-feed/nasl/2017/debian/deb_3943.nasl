# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703943");
  script_cve_id("CVE-2016-10376");
  script_tag(name:"creation_date", value:"2017-08-13 22:00:00 +0000 (Sun, 13 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-06 02:29:00 +0000 (Mon, 06 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3943)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3943");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3943");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gajim' package(s) announced via the DSA-3943 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gajim, a GTK+-based XMPP/Jabber client, unconditionally implements the 'XEP-0146: Remote Controlling Clients' extension, allowing a malicious XMPP server to trigger commands to leak private conversations from encrypted sessions. With this update XEP-0146 support has been disabled by default and made opt-in via the remote_commands option.

For the oldstable distribution (jessie), this problem has been fixed in version 0.16-1+deb8u2.

For the stable distribution (stretch), this problem has been fixed prior to the initial release.

We recommend that you upgrade your gajim packages.");

  script_tag(name:"affected", value:"'gajim' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);