# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61436");
  script_cve_id("CVE-2007-6282", "CVE-2008-0598", "CVE-2008-2729", "CVE-2008-2812", "CVE-2008-2826", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
  script_tag(name:"creation_date", value:"2008-09-04 15:00:42 +0000 (Thu, 04 Sep 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 14:50:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1630)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1630");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1630");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1630 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or arbitrary code execution. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6282

Dirk Nehring discovered a vulnerability in the IPsec code that allows remote users to cause a denial of service by sending a specially crafted ESP packet.

CVE-2008-0598

Tavis Ormandy discovered a vulnerability that allows local users to access uninitialized kernel memory, possibly leaking sensitive data. This issue is specific to the amd64-flavour kernel images.

CVE-2008-2729

Andi Kleen discovered an issue where uninitialized kernel memory was being leaked to userspace during an exception. This issue may allow local users to gain access to sensitive data. Only the amd64-flavour Debian kernel images are affected.

CVE-2008-2812

Alan Cox discovered an issue in multiple tty drivers that allows local users to trigger a denial of service (NULL pointer dereference) and possibly obtain elevated privileges.

CVE-2008-2826

Gabriel Campana discovered an integer overflow in the sctp code that can be exploited by local users to cause a denial of service.

CVE-2008-2931

Miklos Szeredi reported a missing privilege check in the do_change_type() function. This allows local, unprivileged users to change the properties of mount points.

CVE-2008-3272

Tobias Klein reported a locally exploitable data leak in the snd_seq_oss_synth_make_info() function. This may allow local users to gain access to sensitive information.

CVE-2008-3275

Zoltan Sogor discovered a coding error in the VFS that allows local users to exploit a kernel memory leak resulting in a denial of service.

For the stable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-22etch2.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);