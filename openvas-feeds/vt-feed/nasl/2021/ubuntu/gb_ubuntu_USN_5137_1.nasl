# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845125");
  script_cve_id("CVE-2019-19449", "CVE-2020-36385", "CVE-2021-3428", "CVE-2021-34556", "CVE-2021-35477", "CVE-2021-3739", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-3759", "CVE-2021-42252");
  script_tag(name:"creation_date", value:"2021-11-10 02:01:16 +0000 (Wed, 10 Nov 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-19 01:59:00 +0000 (Tue, 19 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5137-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5137-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-kvm, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-kvm' package(s) announced via the USN-5137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the f2fs file system in the Linux kernel did not
properly validate metadata in some situations. An attacker could use this
to construct a malicious f2fs image that, when mounted and operated on,
could cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-19449)

It was discovered that the Infiniband RDMA userspace connection manager
implementation in the Linux kernel contained a race condition leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possible execute arbitrary code.
(CVE-2020-36385)

Wolfgang Frisch discovered that the ext4 file system implementation in the
Linux kernel contained an integer overflow when handling metadata inode
extents. An attacker could use this to construct a malicious ext4 file
system image that, when mounted, could cause a denial of service (system
crash). (CVE-2021-3428)

Benedict Schlueter discovered that the BPF subsystem in the Linux kernel
did not properly protect against Speculative Store Bypass (SSB) side-
channel attacks in some situations. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-34556)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly protect against Speculative Store Bypass (SSB) side-channel
attacks in some situations. A local attacker could possibly use this to
expose sensitive information. (CVE-2021-35477)

It was discovered that the btrfs file system in the Linux kernel did not
properly handle removing a non-existent device id. An attacker with
CAP_SYS_ADMIN could use this to cause a denial of service. (CVE-2021-3739)

It was discovered that the Qualcomm IPC Router protocol implementation in
the Linux kernel did not properly validate metadata in some situations. A
local attacker could use this to cause a denial of service (system crash)
or expose sensitive information. (CVE-2021-3743)

It was discovered that the virtual terminal (vt) device implementation in
the Linux kernel contained a race condition in its ioctl handling that led
to an out-of-bounds read vulnerability. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-3753)

It was discovered that the Linux kernel did not properly account for the
memory usage of certain IPC objects. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2021-3759)

It was discovered that the Aspeed Low Pin Count (LPC) Bus Controller
implementation in the Linux kernel did not properly perform boundary checks
in some situations, allowing out-of-bounds write access. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. In Ubuntu, this issue only affected systems running
armhf kernels. (CVE-2021-42252)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-kvm, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-kvm' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
