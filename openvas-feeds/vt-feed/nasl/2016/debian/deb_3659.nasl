# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703659");
  script_cve_id("CVE-2016-5696", "CVE-2016-6136", "CVE-2016-6480", "CVE-2016-6828");
  script_tag(name:"creation_date", value:"2016-09-03 22:00:00 +0000 (Sat, 03 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3659)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3659");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3659");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3659 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or have other impacts.

CVE-2016-5696

Yue Cao, Zhiyun Qian, Zhongjie Wang, Tuan Dao, and Srikanth V. Krishnamurthy of the University of California, Riverside, and Lisa M. Marvel of the United States Army Research Laboratory discovered that Linux's implementation of the TCP Challenge ACK feature results in a side channel that can be used to find TCP connections between specific IP addresses, and to inject messages into those connections.

Where a service is made available through TCP, this may allow remote attackers to impersonate another connected user to the server or to impersonate the server to another connected user. In case the service uses a protocol with message authentication (e.g. TLS or SSH), this vulnerability only allows denial of service (connection failure). An attack takes tens of seconds, so short-lived TCP connections are also unlikely to be vulnerable.

This may be mitigated by increasing the rate limit for TCP Challenge ACKs so that it is never exceeded: sysctl net.ipv4.tcp_challenge_ack_limit=1000000000

CVE-2016-6136

Pengfei Wang discovered that the audit subsystem has a 'double-fetch' or TOCTTOU bug in its handling of special characters in the name of an executable. Where audit logging of execve() is enabled, this allows a local user to generate misleading log messages.

CVE-2016-6480

Pengfei Wang discovered that the aacraid driver for Adaptec RAID controllers has a 'double-fetch' or TOCTTOU bug in its validation of FIB messages passed through the ioctl() system call. This has no practical security impact in current Debian releases.

CVE-2016-6828

Marco Grassi reported a 'use-after-free' bug in the TCP implementation, which can be triggered by local users. The security impact is unclear, but might include denial of service or privilege escalation.

For the stable distribution (jessie), these problems have been fixed in version 3.16.36-1+deb8u1. In addition, this update contains several changes originally targeted for the upcoming jessie point release.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);