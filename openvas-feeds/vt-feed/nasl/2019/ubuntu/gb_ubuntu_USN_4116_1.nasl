# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844160");
  script_cve_id("CVE-2018-20856", "CVE-2019-10638", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-3900");
  script_tag(name:"creation_date", value:"2019-09-03 02:03:33 +0000 (Tue, 03 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4116-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4116-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a use-after-free error existed in the block layer
subsystem of the Linux kernel when certain failure conditions occurred. A
local attacker could possibly use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-20856)

Amit Klein and Benny Pinkas discovered that the Linux kernel did not
sufficiently randomize IP ID values generated for connectionless networking
protocols. A remote attacker could use this to track particular Linux
devices. (CVE-2019-10638)

Praveen Pandey discovered that the Linux kernel did not properly validate
sent signals in some situations on PowerPC systems with transactional
memory disabled. A local attacker could use this to cause a denial of
service. (CVE-2019-13648)

It was discovered that the floppy driver in the Linux kernel did not
properly validate meta data, leading to a buffer overread. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2019-14283)

It was discovered that the floppy driver in the Linux kernel did not
properly validate ioctl() calls, leading to a division-by-zero. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2019-14284)

Jason Wang discovered that an infinite loop vulnerability existed in the
virtio net driver in the Linux kernel. A local attacker in a guest VM could
possibly use this to cause a denial of service in the host system.
(CVE-2019-3900)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
