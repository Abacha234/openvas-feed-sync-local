# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845256");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-22600", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-39685", "CVE-2021-4083", "CVE-2021-4155", "CVE-2021-4202", "CVE-2022-0330", "CVE-2022-22942");
  script_tag(name:"creation_date", value:"2022-02-23 02:01:27 +0000 (Wed, 23 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 14:23:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5298-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5298-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-5298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Packet network protocol implementation in the
Linux kernel contained a double-free vulnerability. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-22600)

Jurgen Gross discovered that the Xen subsystem within the Linux kernel did
not adequately limit the number of events driver domains (unprivileged PV
backends) could send to other guest VMs. An attacker in a driver domain
could use this to cause a denial of service in other guest VMs.
(CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

Jurgen Gross discovered that the Xen network backend driver in the Linux
kernel did not adequately limit the amount of queued packets when a guest
did not process them. An attacker in a guest VM can use this to cause a
denial of service (excessive kernel memory consumption) in the network
backend domain. (CVE-2021-28714, CVE-2021-28715)

Szymon Heidrich discovered that the USB Gadget subsystem in the Linux
kernel did not properly restrict the size of control requests for certain
gadget types, leading to possible out of bounds reads or writes. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-39685)

Jann Horn discovered a race condition in the Unix domain socket
implementation in the Linux kernel that could result in a read-after-free.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-4083)

Kirill Tkhai discovered that the XFS file system implementation in the
Linux kernel did not calculate size correctly when pre-allocating space in
some situations. A local attacker could use this to expose sensitive
information. (CVE-2021-4155)

Lin Ma discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel contained a race condition, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-4202)

Sushma Venkatesh Reddy discovered that the Intel i915 graphics driver in
the Linux kernel did not perform a GPU TLB flush in some situations. A
local attacker could use this to cause a denial of service or possibly
execute arbitrary code. (CVE-2022-0330)

It was discovered that the VMware Virtual GPU driver in the Linux kernel
did not properly handle certain failure conditions, leading to a stale
entry in the file descriptor table. A local attacker could use this to
expose sensitive information or possibly gain administrative privileges.
(CVE-2022-22942)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
