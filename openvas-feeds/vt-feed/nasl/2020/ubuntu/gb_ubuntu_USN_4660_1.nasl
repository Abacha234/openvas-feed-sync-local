# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844745");
  script_cve_id("CVE-2020-14351", "CVE-2020-14390", "CVE-2020-25211", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-28915", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2020-12-03 04:00:30 +0000 (Thu, 03 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-18 14:15:00 +0000 (Fri, 18 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4660-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4660-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4660-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4660-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the perf subsystem of
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

It was discovered that a race condition existed in the hugetlb sysctl
implementation in the Linux kernel. A privileged attacker could use this to
cause a denial of service (system crash). (CVE-2020-25285)

It was discovered that the block layer subsystem in the Linux kernel did
not properly handle zero-length requests. A local attacker could use this
to cause a denial of service. (CVE-2020-25641)

It was discovered that the HDLC PPP implementation in the Linux kernel did
not properly validate input in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2020-25643)

It was discovered that the GENEVE tunnel implementation in the Linux kernel
when combined with IPSec did not properly select IP routes in some
situations. An attacker could use this to expose sensitive information
(unencrypted network traffic). (CVE-2020-25645)

It was discovered that the framebuffer implementation in the Linux kernel
did not properly perform range checks in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-28915)

It was discovered that Power 9 processors could be coerced to expose
information from the L1 cache in certain situations. A local attacker could
use this to expose sensitive information. (CVE-2020-4788)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
