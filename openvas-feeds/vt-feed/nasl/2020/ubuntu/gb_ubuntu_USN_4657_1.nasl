# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844740");
  script_cve_id("CVE-2020-0427", "CVE-2020-10135", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-14390", "CVE-2020-25211", "CVE-2020-25284", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-25705", "CVE-2020-28915", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2020-12-02 04:00:41 +0000 (Wed, 02 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-18 14:15:00 +0000 (Fri, 18 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4657-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4657-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4657-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4657-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Elena Petrova discovered that the pin controller device tree implementation
in the Linux kernel did not properly handle string references. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-0427)

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered
that legacy pairing and secure-connections pairing authentication in the
Bluetooth protocol could allow an unauthenticated user to complete
authentication without pairing credentials via adjacent access. A
physically proximate attacker could use this to impersonate a previously
paired Bluetooth device. (CVE-2020-10135)

Andy Nguyen discovered that the Bluetooth A2MP implementation in the Linux
kernel did not properly initialize memory in some situations. A physically
proximate remote attacker could use this to expose sensitive information
(kernel memory). (CVE-2020-12352)

It was discovered that a race condition existed in the perf subsystem of
the Linux kernel, leading to a use-after-free vulnerability. An attacker
with access to the perf subsystem could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-14351)

It was discovered that the frame buffer implementation in the Linux kernel
did not properly handle some edge cases in software scrollback. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-14390)

It was discovered that the netfilter connection tracker for netlink in the
Linux kernel did not properly perform bounds checking in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2020-25211)

It was discovered that the Rados block device (rbd) driver in the Linux
kernel did not properly perform privilege checks for access to rbd devices
in some situations. A local attacker could use this to map or unmap rbd
block devices. (CVE-2020-25284)

It was discovered that the HDLC PPP implementation in the Linux kernel did
not properly validate input in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2020-25643)

It was discovered that the GENEVE tunnel implementation in the Linux kernel
when combined with IPSec did not properly select IP routes in some
situations. An attacker could use this to expose sensitive information
(unencrypted network traffic). (CVE-2020-25645)

Keyu Man discovered that the ICMP global rate limiter in the Linux kernel
could be used to assist in scanning open UDP ports. A remote attacker could
use to facilitate attacks on UDP based services that depend on source port
randomization. (CVE-2020-25705)

It was discovered that the framebuffer implementation in the Linux kernel
did not properly perform range checks in certain situations. A local
attacker could use this to expose sensitive information ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
