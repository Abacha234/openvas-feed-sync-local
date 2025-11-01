# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843923");
  script_cve_id("CVE-2018-18397", "CVE-2018-19854", "CVE-2019-6133");
  script_tag(name:"creation_date", value:"2019-03-06 03:08:57 +0000 (Wed, 06 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3901-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3901-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3901-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-oem, linux-signed-oracle' package(s) announced via the USN-3901-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the userfaultd implementation in the Linux kernel
did not properly restrict access to certain ioctls. A local attacker could
use this possibly to modify files. (CVE-2018-18397)

It was discovered that the crypto subsystem of the Linux kernel leaked
uninitialized memory to user space in some situations. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2018-19854)

Jann Horn discovered a race condition in the fork() system call in
the Linux kernel. A local attacker could use this to gain access to
services that cache authorizations. (CVE-2019-6133)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-oem, linux-signed-oracle' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
