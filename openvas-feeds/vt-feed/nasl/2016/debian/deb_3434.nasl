# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703434");
  script_cve_id("CVE-2015-7513", "CVE-2015-7550", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575");
  script_tag(name:"creation_date", value:"2016-01-04 23:00:00 +0000 (Mon, 04 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3434");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3434");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leak.

CVE-2015-7513

It was discovered that a local user permitted to use the x86 KVM subsystem could configure the PIT emulation to cause a denial of service (crash).

CVE-2015-7550

Dmitry Vyukov discovered a race condition in the keyring subsystem that allows a local user to cause a denial of service (crash).

CVE-2015-8543

It was discovered that a local user permitted to create raw sockets could cause a denial-of-service by specifying an invalid protocol number for the socket. The attacker must have the CAP_NET_RAW capability.

CVE-2015-8550

Felix Wilhelm of ERNW discovered that the Xen PV backend drivers may read critical data from shared memory multiple times. This flaw can be used by a guest kernel to cause a denial of service (crash) on the host, or possibly for privilege escalation.

CVE-2015-8551 / CVE-2015-8552 Konrad Rzeszutek Wilk of Oracle discovered that the Xen PCI backend driver does not adequately validate the device state when a guest configures MSIs. This flaw can be used by a guest kernel to cause a denial of service (crash or disk space exhaustion) on the host.

CVE-2015-8569

Dmitry Vyukov discovered a flaw in the PPTP sockets implementation that leads to an information leak to local users.

CVE-2015-8575

David Miller discovered a flaw in the Bluetooth SCO sockets implementation that leads to an information leak to local users.

CVE-2015-8709

Jann Horn discovered a flaw in the permission checks for use of the ptrace feature. A local user who has the CAP_SYS_PTRACE capability within their own user namespace could use this flaw for privilege escalation if a more privileged process ever enters that user namespace. This affects at least the LXC system.

In addition, this update fixes some regressions in the previous update:

#808293

A regression in the UDP implementation prevented freeradius and some other applications from receiving data.

#808602 / #808953 A regression in the USB XHCI driver prevented use of some devices in USB 3 SuperSpeed ports.

#808973

A fix to the radeon driver interacted with an existing bug to cause a crash at boot when using some AMD/ATI graphics cards. This issue only affects wheezy.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.2.73-2+deb7u2. The oldstable distribution (wheezy) is not affected by CVE-2015-8709.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt20-1+deb8u2. CVE-2015-8543 was already fixed in version 3.16.7-ckt20-1+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 4.3.3-3 or earlier.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);