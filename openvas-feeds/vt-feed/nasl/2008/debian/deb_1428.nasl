# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60011");
  script_cve_id("CVE-2007-3104", "CVE-2007-4997", "CVE-2007-5500", "CVE-2007-5904");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1428");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1428");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

This is an update to DSA 1428-1 which omitted a reference to CVE-2007-5904.

CVE-2007-3104

Eric Sandeen provided a backport of Tejun Heo's fix for a local denial of service vulnerability in sysfs. Under memory pressure, a dentry structure maybe reclaimed resulting in a bad pointer dereference causing an oops during a readdir.

CVE-2007-4997

Chris Evans discovered an issue with certain drivers that make use of the Linux kernel's ieee80211 layer. A remote user could generate a malicious 802.11 frame that could result in a denial of service (crash). The ipw2100 driver is known to be affected by this issue, while the ipw2200 is believed not to be.

CVE-2007-5500

Scott James Remnant diagnosed a coding error in the implementation of ptrace which could be used by a local user to cause the kernel to enter an infinite loop.

CVE-2007-5904

Przemyslaw Wegrzyn discovered an issue in the CIFS filesystem that could allow a malicious server to cause a denial of service (crash) by overflowing a buffer.

These problems have been fixed in the stable distribution in version 2.6.18.dfsg.1-13etch5.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch.13etch5

user-mode-linux 2.6.18-1um-2etch.13etch5

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);