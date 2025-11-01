# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69329");
  script_cve_id("CVE-2011-1006", "CVE-2011-1022");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2193");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2193");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libcgroup' package(s) announced via the DSA-2193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in libcgroup, a library to control and monitor control groups:

CVE-2011-1006

Heap-based buffer overflow by converting list of controllers for given task into an array of strings could lead to privilege escalation by a local attacker.

CVE-2011-1022

libcgroup did not properly check the origin of Netlink messages, allowing a local attacker to send crafted Netlink messages which could lead to privilege escalation.

The oldstable distribution (lenny) does not contain libcgroup packages.

For the stable distribution (squeeze), this problem has been fixed in version 0.36.2-3+squeeze1.

For the testing distribution (wheezy) and unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your libcgroup packages.");

  script_tag(name:"affected", value:"'libcgroup' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);