# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703128");
  script_cve_id("CVE-2013-6885", "CVE-2014-8133", "CVE-2014-9419", "CVE-2014-9529", "CVE-2014-9584");
  script_tag(name:"creation_date", value:"2015-01-14 23:00:00 +0000 (Wed, 14 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3128)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3128");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3128");
  script_xref(name:"URL", value:"http://support.amd.com/TechDocs/51810_16h_00h-0Fh_Rev_Guide.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3128 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or information leaks.

CVE-2013-6885

It was discovered that under specific circumstances, a combination of write operations to write-combined memory and locked CPU instructions may cause a core hang on AMD 16h 00h through 0Fh processors. A local user can use this flaw to mount a denial of service (system hang) via a crafted application.

For more information please refer to the AMD CPU erratum 793 in [link moved to references]

CVE-2014-8133

It was found that the espfix functionality can be bypassed by installing a 16-bit RW data segment into GDT instead of LDT (which espfix checks for) and using it for stack. A local unprivileged user could potentially use this flaw to leak kernel stack addresses and thus allowing to bypass the ASLR protection mechanism.

CVE-2014-9419

It was found that on Linux kernels compiled with the 32 bit interfaces (CONFIG_X86_32) a malicious user program can do a partial ASLR bypass through TLS base addresses leak when attacking other programs.

CVE-2014-9529

It was discovered that the Linux kernel is affected by a race condition flaw when doing key garbage collection, allowing local users to cause a denial of service (memory corruption or panic).

CVE-2014-9584

It was found that the Linux kernel does not validate a length value in the Extensions Reference (ER) System Use Field, which allows local users to obtain sensitive information from kernel memory via a crafted iso9660 image.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.65-1+deb7u1. Additionally this update fixes a suspend/resume regression introduced with 3.2.65.

For the upcoming stable distribution (jessie) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);