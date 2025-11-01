# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844758");
  script_cve_id("CVE-2020-0423", "CVE-2020-10135", "CVE-2020-14351", "CVE-2020-25705", "CVE-2020-27152", "CVE-2020-28915", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2020-12-14 04:00:31 +0000 (Mon, 14 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4659-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4659-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4659-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1907262");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-4659-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4659-1 fixed vulnerabilities in the Linux kernel. Unfortunately,
that update introduced a regression in the software raid10 driver
when used with fstrim that could lead to data corruption. This update
fixes the problem.

Original advisory details:

It was discovered that a race condition existed in the binder IPC
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2020-0423)

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered
that legacy pairing and secure-connections pairing authentication in the
Bluetooth protocol could allow an unauthenticated user to complete
authentication without pairing credentials via adjacent access. A
physically proximate attacker could use this to impersonate a previously
paired Bluetooth device. (CVE-2020-10135)

It was discovered that a race condition existed in the perf subsystem of
the Linux kernel, leading to a use-after-free vulnerability. An attacker
with access to the perf subsystem could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-14351)

Keyu Man discovered that the ICMP global rate limiter in the Linux kernel
could be used to assist in scanning open UDP ports. A remote attacker could
use to facilitate attacks on UDP based services that depend on source port
randomization. (CVE-2020-25705)

It was discovered that the KVM hypervisor in the Linux kernel did not
properly handle interrupts in certain situations. A local attacker in a
guest VM could possibly use this to cause a denial of service (host system
crash). (CVE-2020-27152)

It was discovered that the framebuffer implementation in the Linux kernel
did not properly perform range checks in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-28915)

It was discovered that Power 9 processors could be coerced to expose
information from the L1 cache in certain situations. A local attacker could
use this to expose sensitive information. (CVE-2020-4788)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
