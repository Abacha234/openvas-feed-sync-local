# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841718");
  script_cve_id("CVE-2013-6383", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7281");
  script_tag(name:"creation_date", value:"2014-02-20 09:46:53 +0000 (Thu, 20 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2108-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2108-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2108-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-2108-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Linux kernel's compat ioctls for Adaptec
AACRAID scsi raid devices. An unprivileged local user could send
administrative commands to these devices potentially compromising the data
stored on the device. (CVE-2013-6383)

mpd reported an information leak in the recvfrom, recvmmsg, and recvmsg
system calls in the Linux kernel. An unprivileged local user could exploit
this flaw to obtain sensitive information from kernel stack memory.
(CVE-2013-7263)

mpb reported an information leak in the Layer Two Tunneling Protocol (l2tp)
of the Linux kernel. A local user could exploit this flaw to obtain
sensitive information from kernel stack memory. (CVE-2013-7264)

mpb reported an information leak in the Phone Network protocol (phonet) in
the Linux kernel. A local user could exploit this flaw to obtain sensitive
information from kernel stack memory. (CVE-2013-7265)

mpb reported an information leak in the Low-Rate Wireless Personal Area
Networks support (IEEE 802.15.4) in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel stack memory.
(CVE-2013-7281)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
