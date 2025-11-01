# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842668");
  script_cve_id("CVE-2015-8785", "CVE-2016-1575", "CVE-2016-1576");
  script_tag(name:"creation_date", value:"2016-02-28 05:27:27 +0000 (Sun, 28 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2909-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2909-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2909-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1548587");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic' package(s) announced via the USN-2909-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2909-1 fixed vulnerabilities in the Ubuntu 14.10 Linux kernel
backported to Ubuntu 14.04 LTS. An incorrect locking fix caused a
regression that broke graphics displays for Ubuntu 14.04 LTS guests
running the Ubuntu 14.10 backport kernel within VMWare virtual
machines. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 halfdog discovered that OverlayFS, when mounting on top of a FUSE mount,
 incorrectly propagated file attributes, including setuid. A local
 unprivileged attacker could use this to gain privileges. (CVE-2016-1576)

 halfdog discovered that OverlayFS in the Linux kernel incorrectly
 propagated security sensitive extended attributes, such as POSIX ACLs. A
 local unprivileged attacker could use this to gain privileges.
 (CVE-2016-1575)

 It was discovered that the Linux kernel's Filesystem in Userspace (FUSE)
 implementation did not handle initial zero length segments properly. A
 local attacker could use this to cause a denial of service (unkillable
 task). (CVE-2015-8785)");

  script_tag(name:"affected", value:"'linux-lts-utopic' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
