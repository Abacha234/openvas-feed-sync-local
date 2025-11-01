# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702662");
  script_cve_id("CVE-2013-1917", "CVE-2013-1919");
  script_tag(name:"creation_date", value:"2013-04-17 22:00:00 +0000 (Wed, 17 Apr 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2662)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2662");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2662");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2662 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1917

The SYSENTER instruction can be used by PV guests to accelerate system call processing. This instruction, however, leaves the EFLAGS register mostly unmodified. This can be used by malicious or buggy user space to cause the entire host to crash.

CVE-2013-1919

Various IRQ related access control operations may not have the intended effect, potentially permitting a stub domain to grant its client domain access to an IRQ it doesn't have access to itself. This can be used by malicious or buggy stub domains kernels to mount a denial of service attack possibly affecting the whole system.

For the stable distribution (squeeze), these problems have been fixed in version 4.0.1-5.9.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);