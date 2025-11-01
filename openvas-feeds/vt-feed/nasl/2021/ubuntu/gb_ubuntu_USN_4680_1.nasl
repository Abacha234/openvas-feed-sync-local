# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844765");
  script_cve_id("CVE-2019-19770", "CVE-2020-0423", "CVE-2020-10135", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25705", "CVE-2020-27675", "CVE-2020-27777", "CVE-2020-28974");
  script_tag(name:"creation_date", value:"2021-01-11 10:57:13 +0000 (Mon, 11 Jan 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-22 17:18:00 +0000 (Tue, 22 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4680-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4680-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4680-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4680-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that debugfs in the Linux kernel as used by blktrace
contained a use-after-free in some situations. A privileged local attacker
could possibly use this to cause a denial of service (system crash).
(CVE-2019-19770)

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

It was discovered that the console keyboard driver in the Linux kernel
contained a race condition. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2020-25656)

Minh Yuan discovered that the tty driver in the Linux kernel contained race
conditions when handling fonts. A local attacker could possibly use this to
expose sensitive information (kernel memory). (CVE-2020-25668)

Keyu Man discovered that the ICMP global rate limiter in the Linux kernel
could be used to assist in scanning open UDP ports. A remote attacker could
use to facilitate attacks on UDP based services that depend on source port
randomization. (CVE-2020-25705)

Jinoh Kang discovered that the Xen event channel infrastructure in the
Linux kernel contained a race condition. An attacker in guest could
possibly use this to cause a denial of service (dom0 crash).
(CVE-2020-27675)

Daniel Axtens discovered that PowerPC RTAS implementation in the Linux
kernel did not properly restrict memory accesses in some situations. A
privileged local attacker could use this to arbitrarily modify kernel
memory, potentially bypassing kernel lockdown restrictions.
(CVE-2020-27777)

Minh Yuan discovered that the framebuffer console driver in the Linux
kernel did not properly handle fonts in some conditions. A local attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information (kernel memory). (CVE-2020-28974)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
