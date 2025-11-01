# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702926");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2851", "CVE-2014-3122");
  script_tag(name:"creation_date", value:"2014-05-11 22:00:00 +0000 (Sun, 11 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2926)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2926");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2926");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-2926 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, information leaks or privilege escalation:

CVE-2014-0196

Jiri Slaby discovered a race condition in the pty layer, which could lead to denial of service or privilege escalation.

CVE-2014-1737 / CVE-2014-1738 Matthew Daley discovered that missing input sanitising in the FDRAWCMD ioctl and an information leak could result in privilege escalation.

CVE-2014-2851

Incorrect reference counting in the ping_init_sock() function allows denial of service or privilege escalation.

CVE-2014-3122

Incorrect locking of memory can result in local denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.57-3+deb7u1. This update also fixes a regression in the isci driver and suspend problems with certain AMD CPUs (introduced in the updated kernel from the Wheezy 7.5 point release).

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);