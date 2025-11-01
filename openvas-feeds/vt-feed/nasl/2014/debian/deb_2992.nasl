# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702992");
  script_cve_id("CVE-2014-3534", "CVE-2014-4667", "CVE-2014-4943");
  script_tag(name:"creation_date", value:"2014-07-28 22:00:00 +0000 (Mon, 28 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2992)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2992");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2992");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-2992 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation:

CVE-2014-3534

Martin Schwidefsky of IBM discovered that the ptrace subsystem does not properly sanitize the psw mask value. On s390 systems, an unprivileged local user could use this flaw to set address space control bits to kernel space combination and thus gain read/write access to kernel memory.

CVE-2014-4667

Gopal Reddy Kodudula of Nokia Siemens Networks discovered that the sctp_association_free function does not properly manage a certain backlog value, which allows remote attackers to cause a denial of service (socket outage) via a crafted SCTP packet.

CVE-2014-4943

Sasha Levin discovered a flaw in the Linux kernel's point-to-point protocol (PPP) when used with the Layer Two Tunneling Protocol (L2TP). An unprivileged local user could use this flaw for privilege escalation.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.60-1+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 3.14.13-2.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);