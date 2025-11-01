# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702656");
  script_cve_id("CVE-2013-2266");
  script_tag(name:"creation_date", value:"2013-03-29 23:00:00 +0000 (Fri, 29 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2656)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2656");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2656");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-2656 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthew Horsfall of Dyn, Inc. discovered that BIND, a DNS server, is prone to a denial of service vulnerability. A remote attacker could use this flaw to send a specially-crafted DNS query to named that, when processed, would cause named to use an excessive amount of memory, or possibly crash.

For the stable distribution (squeeze), this problem has been fixed in version 1:9.7.3.dfsg-1~squeeze10.

For the testing distribution (wheezy), this problem has been fixed in version 1:9.8.4.dfsg.P1-6+nmu1.

For the unstable distribution (sid), this problem has been fixed in version 1:9.8.4.dfsg.P1-6+nmu1.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);