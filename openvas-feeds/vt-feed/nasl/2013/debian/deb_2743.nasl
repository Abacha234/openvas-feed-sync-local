# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702743");
  script_cve_id("CVE-2013-3077", "CVE-2013-4851", "CVE-2013-5209");
  script_tag(name:"creation_date", value:"2013-08-26 22:00:00 +0000 (Mon, 26 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2743");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2743");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-9' package(s) announced via the DSA-2743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FreeBSD kernel that may lead to a privilege escalation or information leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-3077

Clement Lecigne from the Google Security Team reported an integer overflow in computing the size of a temporary buffer in the IP multicast code, which can result in a buffer which is too small for the requested operation. An unprivileged process can read or write pages of memory which belong to the kernel. These may lead to exposure of sensitive information or allow privilege escalation.

CVE-2013-4851

Rick Macklem, Christopher Key and Tim Zingelman reported that the FreeBSD kernel incorrectly uses client supplied credentials instead of the one configured in exports(5) when filling out the anonymous credential for a NFS export, when -network or -host restrictions are used at the same time. The remote client may supply privileged credentials (e.g. the root user) when accessing a file under the NFS share, which will bypass the normal access checks.

CVE-2013-5209

Julian Seward and Michael Tuexen reported a kernel memory disclosure when initializing the SCTP state cookie being sent in INIT-ACK chunks, a buffer allocated from the kernel stack is not completely initialized. Fragments of kernel memory may be included in SCTP packets and transmitted over the network. For each SCTP session, there are two separate instances in which a 4-byte fragment may be transmitted.

This memory might contain sensitive information, such as portions of the file cache or terminal buffers. This information might be directly useful, or it might be leveraged to obtain elevated privileges in some way. For example, a terminal buffer might include an user-entered password.

For the stable distribution (wheezy), these problems has been fixed in version 9.0-10+deb70.3.

We recommend that you upgrade your kfreebsd-9 packages.");

  script_tag(name:"affected", value:"'kfreebsd-9' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);