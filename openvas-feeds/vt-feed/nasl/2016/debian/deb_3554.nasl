# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703554");
  script_cve_id("CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3960");
  script_tag(name:"creation_date", value:"2016-04-20 22:00:00 +0000 (Wed, 20 Apr 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Debian: Security Advisory (DSA-3554)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3554");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3554");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3554 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-3158, CVE-2016-3159 (XSA-172) Jan Beulich from SUSE discovered that Xen does not properly handle writes to the hardware FSW.ES bit when running on AMD64 processors. A malicious domain can take advantage of this flaw to obtain address space usage and timing information, about another domain, at a fairly low rate.

CVE-2016-3960 (XSA-173) Ling Liu and Yihan Lian of the Cloud Security Team, Qihoo 360 discovered an integer overflow in the x86 shadow pagetable code. A HVM guest using shadow pagetables can cause the host to crash. A PV guest using shadow pagetables (i.e. being migrated) with PV superpages enabled (which is not the default) can crash the host, or corrupt hypervisor memory, potentially leading to privilege escalation.

For the stable distribution (jessie), these problems have been fixed in version 4.4.1-9+deb8u5.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);