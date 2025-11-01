# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60047");
  script_cve_id("CVE-2006-6058", "CVE-2007-5966", "CVE-2007-6063", "CVE-2007-6206", "CVE-2007-6417");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1436");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1436");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1436 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-6058

LMH reported an issue in the minix filesystem that allows local users with mount privileges to create a DoS (printk flood) by mounting a specially crafted corrupt filesystem.

CVE-2007-5966

Warren Togami discovered an issue in the hrtimer subsystem that allows a local user to cause a DoS (soft lockup) by requesting a timer sleep for a long period of time leading to an integer overflow.

CVE-2007-6063

Venustech AD-LAB discovered a buffer overflow in the isdn ioctl handling, exploitable by a local user.

CVE-2007-6206

Blake Frantz discovered that when a core file owned by a non-root user exists, and a root-owned process dumps core over it, the core file retains its original ownership. This could be used by a local user to gain access to sensitive information.

CVE-2007-6417

Hugh Dickins discovered an issue in the tmpfs filesystem where, under a rare circumstance, a kernel page may be improperly cleared, leaking sensitive kernel memory to userspace or resulting in a DoS (crash).

These problems have been fixed in the stable distribution in version 2.6.18.dfsg.1-13etch6.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch.13etch6

user-mode-linux 2.6.18-1um-2etch.13etch6

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);