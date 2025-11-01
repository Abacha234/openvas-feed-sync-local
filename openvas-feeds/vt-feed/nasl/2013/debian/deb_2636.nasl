# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702636");
  script_cve_id("CVE-2012-2625", "CVE-2012-4544", "CVE-2012-5511", "CVE-2012-5634", "CVE-2012-6333", "CVE-2013-0153");
  script_tag(name:"creation_date", value:"2013-03-02 23:00:00 +0000 (Sat, 02 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2636)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2636");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2636");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2636 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-4544

Insufficient validation of kernel or ramdisk sizes in the Xen PV domain builder could result in denial of service.

CVE-2012-5511

Several HVM control operations performed insufficient validation of input, which could result in denial of service through resource exhaustion.

CVE-2012-5634

Incorrect interrupt handling when using VT-d hardware could result in denial of service.

CVE-2013-0153

Insufficient restriction of interrupt access could result in denial of service.

For the stable distribution (squeeze), these problems have been fixed in version 4.0.1-5.8.

For the testing distribution (wheezy), these problems have been fixed in version 4.1.4-2.

For the unstable distribution (sid), these problems have been fixed in version 4.1.4-2.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);