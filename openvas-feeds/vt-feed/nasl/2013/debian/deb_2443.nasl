# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702443");
  script_cve_id("CVE-2009-4307", "CVE-2011-1833", "CVE-2011-4127", "CVE-2011-4347", "CVE-2012-0045", "CVE-2012-1090", "CVE-2012-1097");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:14:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-2443)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2443");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2443");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2443 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4307

Nageswara R Sastry reported an issue in the ext4 filesystem. Local users with the privileges to mount a filesystem can cause a denial of service (BUG) by providing a s_log_groups_per_flex value greater than 31.

CVE-2011-1833

Vasiliy Kulikov of Openwall and Dan Rosenberg discovered an information leak in the eCryptfs filesystem. Local users were able to mount arbitrary directories.

CVE-2011-4347

Sasha Levin reported an issue in the device assignment functionality in KVM. Local users with permission to access /dev/kvm could assign unused pci devices to a guest and cause a denial of service (crash).

CVE-2012-0045

Stephan Barwolf reported an issue in KVM. Local users in a 32-bit guest running on a 64-bit system can crash the guest with a syscall instruction.

CVE-2012-1090

CAI Qian reported an issue in the CIFS filesystem. A reference count leak can occur during the lookup of special files, resulting in a denial of service (oops) on umount.

CVE-2012-1097

H. Peter Anvin reported an issue in the regset infrastructure. Local users can cause a denial of service (NULL pointer dereference) by triggering the write methods of readonly regsets.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.32-41squeeze2.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:



Debian 6.0 (squeeze)

user-mode-linux

2.6.32-1um-4+41squeeze2

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

Thanks to Micah Anderson for proof reading this text.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);