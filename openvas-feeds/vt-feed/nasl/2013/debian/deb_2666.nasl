# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702666");
  script_cve_id("CVE-2013-1918", "CVE-2013-1952", "CVE-2013-1964");
  script_tag(name:"creation_date", value:"2013-05-11 22:00:00 +0000 (Sat, 11 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2666)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2666");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2666");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2666 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1918

(XSA 45) several long latency operations are not preemptible.

Some page table manipulation operations for PV guests were not made preemptible, allowing a malicious or buggy PV guest kernel to mount a denial of service attack affecting the whole system.

CVE-2013-1952

(XSA 49) VT-d interrupt remapping source validation flaw for bridges.

Due to missing source validation on interrupt remapping table entries for MSI interrupts set up by bridge devices, a malicious domain with access to such a device can mount a denial of service attack affecting the whole system.

CVE-2013-1964

(XSA 50) grant table hypercall acquire/release imbalance.

When releasing a particular, non-transitive grant after doing a grant copy operation, Xen incorrectly releases an unrelated grant reference, leading possibly to a crash of the host system. Furthermore information leakage or privilege escalation cannot be ruled out.

For the oldstable distribution (squeeze), these problems have been fixed in version 4.0.1-5.11.

For the stable distribution (wheezy), these problems have been fixed in version 4.1.4-3+deb7u1.

For the testing distribution (jessie), these problems have been fixed in version 4.1.4-4.

For the unstable distribution (sid), these problems have been fixed in version 4.1.4-4.

Note that for the stable (wheezy), testing and unstable distribution, CVE-2013-1964 (XSA 50) was already fixed in version 4.1.4-3.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);