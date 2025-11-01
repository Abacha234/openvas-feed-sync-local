# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844929");
  script_cve_id("CVE-2020-25639", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-28375", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29266", "CVE-2021-29646", "CVE-2021-29650", "CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491");
  script_tag(name:"creation_date", value:"2021-05-12 03:00:53 +0000 (Wed, 12 May 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4949-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4949-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4949-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-4949-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryota Shiga discovered that the eBPF implementation in the Linux kernel did
not properly verify that a BPF program only reserved as much memory for a
ring buffer as was allocated. A local attacker could use this to cause a
denial of service (system crash) or execute arbitrary code. (CVE-2021-3489)

Manfred Paul discovered that the eBPF implementation in the Linux kernel
did not properly track bounds on bitwise operations. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2021-3490)

Billy Jheng Bing-Jhong discovered that the io_uring implementation of the
Linux kernel did not properly enforce the MAX_RW_COUNT limit in some
situations. A local attacker could use this to cause a denial of service
(system crash) or execute arbitrary code. (CVE-2021-3491)

It was discovered that the Nouveau GPU driver in the Linux kernel did not
properly handle error conditions in some situations. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25639)

Olivier Benjamin, Norbert Manthey, Martin Mazein, and Jan H. Schonherr
discovered that the Xen paravirtualization backend in the Linux kernel did
not properly propagate errors to frontend drivers in some situations. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-26930)

Jan Beulich discovered that multiple Xen backends in the Linux kernel did
not properly handle certain error conditions under paravirtualization. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-26931)

It was discovered that the fastrpc driver in the Linux kernel did not
prevent user space applications from sending kernel RPC messages. A local
attacker could possibly use this to gain elevated privileges.
(CVE-2021-28375)

It was discovered that the Freescale Gianfar Ethernet driver for the Linux
kernel did not properly handle receive queue overrun when jumbo frames were
enabled in some situations. An attacker could use this to cause a denial of
service (system crash). (CVE-2021-29264)

It was discovered that the USB/IP driver in the Linux kernel contained race
conditions during the update of local and shared status. An attacker could
use this to cause a denial of service (system crash). (CVE-2021-29265)

It was discovered that the vDPA backend virtio driver in the Linux kernel
contained a use-after-free vulnerability. An attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2021-29266)

It was discovered that the TIPC protocol implementation in the Linux kernel
did not properly validate passed encryption key sizes. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2021-29646)

It was discovered that a race condition existed in the netfilter subsystem
of the Linux kernel when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
