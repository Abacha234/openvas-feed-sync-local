# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70555");
  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_tag(name:"creation_date", value:"2012-02-13 16:43:28 +0000 (Mon, 13 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2341");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2341");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel, xulrunner' package(s) announced via the DSA-2341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Iceweasel, a web browser based on Firefox. The included XULRunner library provides rendering services for several other applications included in Debian.

CVE-2011-3647

moz_bug_r_a4 discovered a privilege escalation vulnerability in addon handling.

CVE-2011-3648

Yosuke Hasegawa discovered that incorrect handling of Shift-JIS encodings could lead to cross-site scripting.

CVE-2011-3650

Marc Schoenefeld discovered that profiling the JavaScript code could lead to memory corruption.

For the oldstable distribution (lenny), this problem has been fixed in version 1.9.0.19-15 of the xulrunner source package.

For the stable distribution (squeeze), this problem has been fixed in version 3.5.16-11.

For the unstable distribution (sid), this problem has been fixed in version 8.0-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel, xulrunner' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);