# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702952");
  script_cve_id("CVE-2014-1453", "CVE-2014-3000", "CVE-2014-3880");
  script_tag(name:"creation_date", value:"2014-06-04 22:00:00 +0000 (Wed, 04 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2952)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2952");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2952");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-9' package(s) announced via the DSA-2952 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FreeBSD kernel that may lead to a denial of service or possibly disclosure of kernel memory. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-1453

A remote, authenticated attacker could cause the NFS server become deadlocked, resulting in a denial of service.

CVE-2014-3000: An attacker who can send a series of specifically crafted packets with a connection could cause a denial of service situation by causing the kernel to crash. Additionally, because the undefined on stack memory may be overwritten by other kernel threads, while difficult, it may be possible for an attacker to construct a carefully crafted attack to obtain portion of kernel memory via a connected socket. This may result in the disclosure of sensitive information such as login credentials, etc. before or even without crashing the system.

CVE-2014-3880

A local attacker can trigger a kernel crash (triple fault) with potential data loss, related to the execve/fexecve system calls. Reported by Ivo De Decker.

For the stable distribution (wheezy), these problems have been fixed in version 9.0-10+deb70.7.

For the unstable (sid) and testing (jessie) distributions, these problems are fixed in kfreebsd-10 version 10.0-6.

We recommend that you upgrade your kfreebsd-9 packages.");

  script_tag(name:"affected", value:"'kfreebsd-9' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);