# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702389");
  script_cve_id("CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2898", "CVE-2011-3353", "CVE-2011-4077", "CVE-2011-4110", "CVE-2011-4127", "CVE-2011-4611", "CVE-2011-4622", "CVE-2011-4914");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 17:33:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-2389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2389");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2389");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-2183

Andrea Righi reported an issue in KSM, a memory-saving de-duplication feature. By exploiting a race with exiting tasks, local users can cause a kernel oops, resulting in a denial of service.

CVE-2011-2213

Dan Rosenberg discovered an issue in the INET socket monitoring interface. Local users could cause a denial of service by injecting code and causing the kernel to execute an infinite loop.

CVE-2011-2898

Eric Dumazet reported an information leak in the raw packet socket implementation.

CVE-2011-3353

Han-Wen Nienhuys reported a local denial of service issue in the FUSE (Filesystem in Userspace) support in the Linux kernel. Local users could cause a buffer overflow, leading to a kernel oops and resulting in a denial of service.

CVE-2011-4077

Carlos Maiolino reported an issue in the XFS filesystem. A local user with the ability to mount a filesystem could corrupt memory resulting in a denial of service or possibly gain elevated privileges.

CVE-2011-4110

David Howells reported an issue in the kernel's access key retention system which allow local users to cause a kernel oops leading to a denial of service.

CVE-2011-4127

Paolo Bonzini of Red Hat reported an issue in the ioctl passthrough support for SCSI devices. Users with permission to access restricted portions of a device (e.g. a partition or a logical volume) can obtain access to the entire device by way of the SG_IO ioctl. This could be exploited by a local user or privileged VM guest to achieve a privilege escalation.

CVE-2011-4611

Maynard Johnson reported an issue with the perf support on POWER7 systems that allows local users to cause a denial of service.

CVE-2011-4622

Jan Kiszka reported an issue in the KVM PIT timer support. Local users with the permission to use KVM can cause a denial of service by starting a PIT timer without first setting up the irqchip.

CVE-2011-4914

Ben Hutchings reported various bounds checking issues within the ROSE protocol support in the kernel. Remote users could possibly use this to gain access to sensitive memory or cause a denial of service.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.32-39squeeze1. Updates for issues impacting the oldstable distribution (lenny) will be available soon.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:



Debian 6.0 (squeeze)

user-mode-linux

2.6.32-1um-4+39squeeze1

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);