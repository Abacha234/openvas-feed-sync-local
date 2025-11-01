# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842667");
  script_cve_id("CVE-2015-7550", "CVE-2015-8543", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8785", "CVE-2016-1575", "CVE-2016-1576");
  script_tag(name:"creation_date", value:"2016-02-28 05:27:14 +0000 (Sun, 28 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2910-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2910-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2910-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1548587");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-vivid' package(s) announced via the USN-2910-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2910-1 fixed vulnerabilities in the Ubuntu 15.04 Linux kernel
backported to Ubuntu 14.04 LTS. An incorrect locking fix caused a
regression that broke graphics displays for Ubuntu 14.04 LTS guests
running the Ubuntu 15.04 backport kernel within VMWare virtual
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

 It was discovered that the Linux kernel keyring subsystem contained a race
 between read and revoke operations. A local attacker could use this to
 cause a denial of service (system crash). (CVE-2015-7550)

 Guo Yong Gang discovered that the Linux kernel networking implementation did
 not validate protocol identifiers for certain protocol families, A local
 attacker could use this to cause a denial of service (system crash) or
 possibly gain administrative privileges. (CVE-2015-8543)

 Dmitry Vyukov discovered that the pptp implementation in the Linux kernel
 did not verify an address length when setting up a socket. A local attacker
 could use this to craft an application that exposed sensitive information
 from kernel memory. (CVE-2015-8569)

 David Miller discovered that the Bluetooth implementation in the Linux
 kernel did not properly validate the socket address length for Synchronous
 Connection-Oriented (SCO) sockets. A local attacker could use this to
 expose sensitive information. (CVE-2015-8575)

 It was discovered that the Linux kernel's Filesystem in Userspace (FUSE)
 implementation did not handle initial zero length segments properly. A
 local attacker could use this to cause a denial of service (unkillable
 task). (CVE-2015-8785)");

  script_tag(name:"affected", value:"'linux-lts-vivid' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
