# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703313");
  script_cve_id("CVE-2015-3290", "CVE-2015-3291", "CVE-2015-4167", "CVE-2015-5157", "CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"creation_date", value:"2015-07-22 22:00:00 +0000 (Wed, 22 Jul 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3313)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3313");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3313");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3313 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation or denial of service.

CVE-2015-3290

Andy Lutomirski discovered that the Linux kernel does not properly handle nested NMIs. A local, unprivileged user could use this flaw for privilege escalation.

CVE-2015-3291

Andy Lutomirski discovered that under certain conditions a malicious userspace program can cause the kernel to skip NMIs leading to a denial of service.

CVE-2015-4167

Carl Henrik Lunde discovered that the UDF implementation is missing a necessary length check. A local user that can mount devices could use this flaw to crash the system.

CVE-2015-5157

Petr Matousek and Andy Lutomirski discovered that an NMI that interrupts userspace and encounters an IRET fault is incorrectly handled. A local, unprivileged user could use this flaw for denial of service or possibly for privilege escalation.

CVE-2015-5364

It was discovered that the Linux kernel does not properly handle invalid UDP checksums. A remote attacker could exploit this flaw to cause a denial of service using a flood of UDP packets with invalid checksums.

CVE-2015-5366

It was discovered that the Linux kernel does not properly handle invalid UDP checksums. A remote attacker can cause a denial of service against applications that use epoll by injecting a single packet with an invalid checksum.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt11-1+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 4.0.8-2 or earlier versions.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);