# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703329");
  script_cve_id("CVE-2015-3212", "CVE-2015-4700", "CVE-2015-5697", "CVE-2015-5707");
  script_tag(name:"creation_date", value:"2015-08-11 06:31:25 +0000 (Tue, 11 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3329)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3329");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3329");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3329 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leak.

CVE-2015-1333

Colin Ian King discovered a flaw in the add_key function of the Linux kernel's keyring subsystem. A local user can exploit this flaw to cause a denial of service due to memory exhaustion.

CVE-2015-3212

Ji Jianwen of Red Hat Engineering discovered a flaw in the handling of the SCTPs automatic handling of dynamic multi-homed connections. A local attacker could use this flaw to cause a crash or potentially for privilege escalation.

CVE-2015-4692

A NULL pointer dereference flaw was found in the kvm_apic_has_events function in the KVM subsystem. A unprivileged local user could exploit this flaw to crash the system kernel resulting in denial of service.

CVE-2015-4700

Daniel Borkmann discovered a flaw in the Linux kernel implementation of the Berkeley Packet Filter which can be used by a local user to crash the system.

CVE-2015-5364

It was discovered that the Linux kernel does not properly handle invalid UDP checksums. A remote attacker could exploit this flaw to cause a denial of service using a flood of UDP packets with invalid checksums.

CVE-2015-5366

It was discovered that the Linux kernel does not properly handle invalid UDP checksums. A remote attacker can cause a denial of service against applications that use epoll by injecting a single packet with an invalid checksum.

CVE-2015-5697

A flaw was discovered in the md driver in the Linux kernel leading to an information leak.

CVE-2015-5706

An user triggerable use-after-free vulnerability in path lookup in the Linux kernel could potentially lead to privilege escalation.

CVE-2015-5707

An integer overflow in the SCSI generic driver in the Linux kernel was discovered. A local user with write permission on a SCSI generic device could potentially exploit this flaw for privilege escalation.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.2.68-1+deb7u3. CVE-2015-1333, CVE-2015-4692 and CVE-2015-5706 do not affect the wheezy distribution.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt11-1+deb8u3, except CVE-2015-5364 and CVE-2015-5366 which were fixed already in DSA-3313-1.

For the unstable distribution (sid), these problems have been fixed in version 4.1.3-1 or earlier versions.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);