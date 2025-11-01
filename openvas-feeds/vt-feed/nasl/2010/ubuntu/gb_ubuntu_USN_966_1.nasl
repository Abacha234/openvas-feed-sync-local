# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840476");
  script_cve_id("CVE-2008-7256", "CVE-2010-1173", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1451", "CVE-2010-1636", "CVE-2010-1641", "CVE-2010-1643", "CVE-2010-2071", "CVE-2010-2492");
  script_tag(name:"creation_date", value:"2010-08-06 08:34:50 +0000 (Fri, 06 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:33:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-966-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-966-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-966-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2, linux-mvl-dove, linux-source-2.6.15, linux-ti-omap' package(s) announced via the USN-966-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Junjiro R. Okajima discovered that knfsd did not correctly handle
strict overcommit. A local attacker could exploit this to crash knfsd,
leading to a denial of service. (Only Ubuntu 6.06 LTS and 8.04 LTS were
affected.) (CVE-2008-7256, CVE-2010-1643)

Chris Guo, Jukka Taimisto, and Olli Jarva discovered that SCTP did
not correctly handle invalid parameters. A remote attacker could send
specially crafted traffic that could crash the system, leading to a
denial of service. (CVE-2010-1173)

Mario Mikocevic discovered that GFS2 did not correctly handle certain
quota structures. A local attacker could exploit this to crash the
system, leading to a denial of service. (Ubuntu 6.06 LTS was not
affected.) (CVE-2010-1436)

Toshiyuki Okajima discovered that the kernel keyring did not correctly
handle dead keyrings. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-1437)

Brad Spengler discovered that Sparc did not correctly implement
non-executable stacks. This made userspace applications vulnerable to
exploits that would have been otherwise blocked due to non-executable
memory protections. (Ubuntu 10.04 LTS was not affected.) (CVE-2010-1451)

Dan Rosenberg discovered that the btrfs clone function did not correctly
validate permissions. A local attacker could exploit this to read
sensitive information, leading to a loss of privacy. (Only Ubuntu 9.10
was affected.) (CVE-2010-1636)

Dan Rosenberg discovered that GFS2 set_flags function did not correctly
validate permissions. A local attacker could exploit this to gain
access to files, leading to a loss of privacy and potential privilege
escalation. (Ubuntu 6.06 LTS was not affected.) (CVE-2010-1641)

Shi Weihua discovered that btrfs xattr_set_acl function did not
correctly validate permissions. A local attacker could exploit
this to gain access to files, leading to a loss of privacy and
potential privilege escalation. (Only Ubuntu 9.10 and 10.04 LTS were
affected.) (CVE-2010-2071)

Andre Osterhues discovered that eCryptfs did not correctly calculate
hash values. A local attacker with certain uids could exploit this to
crash the system or potentially gain root privileges. (Ubuntu 6.06 LTS
was not affected.) (CVE-2010-2492)");

  script_tag(name:"affected", value:"'linux, linux-ec2, linux-mvl-dove, linux-source-2.6.15, linux-ti-omap' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
