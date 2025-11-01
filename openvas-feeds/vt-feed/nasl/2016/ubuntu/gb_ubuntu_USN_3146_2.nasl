# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842964");
  script_cve_id("CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8658", "CVE-2016-9644");
  script_tag(name:"creation_date", value:"2016-12-01 04:39:01 +0000 (Thu, 01 Dec 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)");

  script_name("Ubuntu: Security Advisory (USN-3146-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3146-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3146-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-xenial, linux-meta-lts-xenial' package(s) announced via the USN-3146-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3146-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that the __get_user_asm_ex implementation in the Linux
kernel for x86/x86_64 contained extended asm statements that were
incompatible with the exception table. A local attacker could use this to
gain administrative privileges. (CVE-2016-9644)

Andreas Gruenbacher and Jan Kara discovered that the filesystem
implementation in the Linux kernel did not clear the setgid bit during a
setxattr call. A local attacker could use this to possibly elevate group
privileges. (CVE-2016-7097)

Marco Grassi discovered that the driver for Areca RAID Controllers in the
Linux kernel did not properly validate control messages. A local attacker
could use this to cause a denial of service (system crash) or possibly gain
privileges. (CVE-2016-7425)

Daxing Guo discovered a stack-based buffer overflow in the Broadcom
IEEE802.11n FullMAC driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly gain
privileges. (CVE-2016-8658)");

  script_tag(name:"affected", value:"'linux-lts-xenial, linux-meta-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
