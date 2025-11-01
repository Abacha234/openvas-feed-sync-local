# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704078");
  script_cve_id("CVE-2017-5754");
  script_tag(name:"creation_date", value:"2018-01-03 23:00:00 +0000 (Wed, 03 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 11:31:00 +0000 (Tue, 05 May 2020)");

  script_name("Debian: Security Advisory (DSA-4078)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4078");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4078");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4078 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple researchers have discovered a vulnerability in Intel processors, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Meltdown and is addressed in the Linux kernel for the Intel x86-64 architecture by a patch set named Kernel Page Table Isolation, enforcing a near complete separation of the kernel and userspace address maps and preventing the attack. This solution might have a performance impact, and can be disabled at boot time by passing pti=off to the kernel command line.

We also identified a regression for ancient userspaces using the vsyscall interface, for example chroot and containers using (e)glibc 2.13 and older, including those based on Debian 7 or RHEL/CentOS 6. This regression will be fixed in a later update.

The other vulnerabilities (named Spectre) published at the same time are not addressed in this update and will be fixed in a later update.

For the oldstable distribution (jessie), this problem will be fixed in a separate update.

For the stable distribution (stretch), this problem has been fixed in version 4.9.65-3+deb9u2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);