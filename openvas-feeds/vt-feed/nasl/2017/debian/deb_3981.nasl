# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703981");
  script_cve_id("CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-1000251", "CVE-2017-1000370", "CVE-2017-1000371", "CVE-2017-1000380", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-7518");
  script_tag(name:"creation_date", value:"2017-09-19 22:00:00 +0000 (Tue, 19 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)");

  script_name("Debian: Security Advisory (DSA-3981)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3981");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3981");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3981 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to privilege escalation, denial of service or information leaks.

CVE-2017-7518

Andy Lutomirski discovered that KVM is prone to an incorrect debug exception (#DB) error occurring while emulating a syscall instruction. A process inside a guest can take advantage of this flaw for privilege escalation inside a guest.

CVE-2017-7558 (stretch only) Stefano Brivio of Red Hat discovered that the SCTP subsystem is prone to a data leak vulnerability due to an out-of-bounds read flaw, allowing to leak up to 100 uninitialized bytes to userspace.

CVE-2017-10661 (jessie only) Dmitry Vyukov of Google reported that the timerfd facility does not properly handle certain concurrent operations on a single file descriptor. This allows a local attacker to cause a denial of service or potentially execute arbitrary code.

CVE-2017-11600

Bo Zhang reported that the xfrm subsystem does not properly validate one of the parameters to a netlink message. Local users with the CAP_NET_ADMIN capability can use this to cause a denial of service or potentially to execute arbitrary code.

CVE-2017-12134 / #866511 / XSA-229 Jan H. Schoenherr of Amazon discovered that when Linux is running in a Xen PV domain on an x86 system, it may incorrectly merge block I/O requests. A buggy or malicious guest may trigger this bug in dom0 or a PV driver domain, causing a denial of service or potentially execution of arbitrary code. This issue can be mitigated by disabling merges on the underlying back-end block devices, e.g.: echo 2 > /sys/block/nvme0n1/queue/nomerges

CVE-2017-12146 (stretch only) Adrian Salido of Google reported a race condition in access to the driver_override attribute for platform devices in sysfs. If unprivileged users are permitted to access this attribute, this might allow them to gain privileges.

CVE-2017-12153

Bo Zhang reported that the cfg80211 (wifi) subsystem does not properly validate the parameters to a netlink message. Local users with the CAP_NET_ADMIN capability (in any user namespace with a wifi device) can use this to cause a denial of service.

CVE-2017-12154

Jim Mattson of Google reported that the KVM implementation for Intel x86 processors did not correctly handle certain nested hypervisor configurations. A malicious guest (or nested guest in a suitable L1 hypervisor) could use this for denial of service.

CVE-2017-14106

Andrey Konovalov discovered that a user-triggerable division by zero in the tcp_disconnect() function could result in local denial of service.

CVE-2017-14140

Otto Ebeling reported that the move_pages() system call performed insufficient validation of the UIDs of the calling and target processes, resulting in a partial ASLR bypass. This made it easier for local users to exploit vulnerabilities in programs installed with the set-UID permission bit set.

CVE-2017-14156

sohu0106 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);