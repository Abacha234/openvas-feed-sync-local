# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844443");
  script_cve_id("CVE-2019-19377", "CVE-2019-19769", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12657", "CVE-2020-12826");
  script_tag(name:"creation_date", value:"2020-05-22 03:00:20 +0000 (Fri, 22 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-11 00:15:00 +0000 (Fri, 11 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4369-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4369-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.3, linux-gcp, linux-gcp-5.3, linux-gke-5.3, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.3, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.3, linux-meta-raspi2, linux-oracle, linux-oracle-5.3, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-oracle, linux-signed-oracle-5.3' package(s) announced via the USN-4369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the btrfs implementation in the Linux kernel did not
properly detect that a block was marked dirty in some situations. An
attacker could use this to specially craft a file system image that, when
unmounted, could cause a denial of service (system crash). (CVE-2019-19377)

Tristan Madani discovered that the file locking implementation in the Linux
kernel contained a race condition. A local attacker could possibly use this
to cause a denial of service or expose sensitive information.
(CVE-2019-19769)

It was discovered that the Serial CAN interface driver in the Linux kernel
did not properly initialize data. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2020-11494)

It was discovered that the linux kernel did not properly validate certain
mount options to the tmpfs virtual memory file system. A local attacker
with the ability to specify mount options could use this to cause a denial
of service (system crash). (CVE-2020-11565)

It was discovered that the OV51x USB Camera device driver in the Linux
kernel did not properly validate device metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2020-11608)

It was discovered that the STV06XX USB Camera device driver in the Linux
kernel did not properly validate device metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2020-11609)

It was discovered that the Xirlink C-It USB Camera device driver in the
Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-11668)

It was discovered that the block layer in the Linux kernel contained a race
condition leading to a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.3, linux-gcp, linux-gcp-5.3, linux-gke-5.3, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.3, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.3, linux-meta-raspi2, linux-oracle, linux-oracle-5.3, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-oracle, linux-signed-oracle-5.3' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
