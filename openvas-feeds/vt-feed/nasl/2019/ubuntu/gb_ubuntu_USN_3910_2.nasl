# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843934");
  script_cve_id("CVE-2017-18241", "CVE-2018-1120", "CVE-2018-19985", "CVE-2018-7740", "CVE-2019-6133");
  script_tag(name:"creation_date", value:"2019-03-16 03:08:49 +0000 (Sat, 16 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3910-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3910-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3910-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial, linux-signed-lts-xenial' package(s) announced via the USN-3910-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3910-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that the f2fs filesystem implementation in the Linux
kernel did not handle the noflush_merge mount option correctly. An attacker
could use this to cause a denial of service (system crash).
(CVE-2017-18241)

It was discovered that the procfs filesystem did not properly handle
processes mapping some memory elements onto files. A local attacker could
use this to block utilities that examine the procfs filesystem to report
operating system state, such as ps(1). (CVE-2018-1120)

Hui Peng and Mathias Payer discovered that the Option USB High Speed driver
in the Linux kernel did not properly validate metadata received from the
device. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2018-19985)

It was discovered that multiple integer overflows existed in the hugetlbfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2018-7740)

Jann Horn discovered a race condition in the fork() system call in the
Linux kernel. A local attacker could use this to gain access to services
that cache authorizations. (CVE-2019-6133)");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial, linux-signed-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
