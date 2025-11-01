# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64378");
  script_cve_id("CVE-2007-2807", "CVE-2009-1789");
  script_tag(name:"creation_date", value:"2009-07-15 02:21:35 +0000 (Wed, 15 Jul 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1826)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1826");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1826");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eggdrop' package(s) announced via the DSA-1826 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in eggdrop, an advanced IRC robot. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2807

It was discovered that eggdrop is vulnerable to a buffer overflow, which could result in a remote user executing arbitrary code. The previous DSA (DSA-1448-1) did not fix the issue correctly.

CVE-2009-1789

It was discovered that eggdrop is vulnerable to a denial of service attack, that allows remote attackers to cause a crash via a crafted PRIVMSG.

For the stable distribution (lenny), these problems have been fixed in version 1.6.19-1.1+lenny1.

For the old stable distribution (etch), these problems have been fixed in version 1.6.18-1etch2.

For the unstable distribution (sid), this problem has been fixed in version 1.6.19-1.2

We recommend that you upgrade your eggdrop package.");

  script_tag(name:"affected", value:"'eggdrop' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);