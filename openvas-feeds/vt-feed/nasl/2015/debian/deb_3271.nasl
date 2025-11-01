# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703271");
  script_cve_id("CVE-2013-7441", "CVE-2015-0847");
  script_tag(name:"creation_date", value:"2015-05-22 22:00:00 +0000 (Fri, 22 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3271)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3271");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3271");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nbd' package(s) announced via the DSA-3271 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tuomas Rasanen discovered that unsafe signal handling in nbd-server, the server for the Network Block Device protocol, could allow remote attackers to cause a deadlock in the server process and thus a denial of service.

Tuomas Rasanen also discovered that the modern-style negotiation was carried out in the main server process before forking the actual client handler. This could allow a remote attacker to cause a denial of service (crash) by querying a non-existent export. This issue only affected the oldstable distribution (wheezy).

For the oldstable distribution (wheezy), these problems have been fixed in version 1:3.2-4~deb7u5.

For the stable distribution (jessie), these problems have been fixed in version 1:3.8-4+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1:3.10-1.

For the unstable distribution (sid), these problems have been fixed in version 1:3.10-1.

We recommend that you upgrade your nbd packages.");

  script_tag(name:"affected", value:"'nbd' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);