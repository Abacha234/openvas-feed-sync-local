# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703093");
  script_cve_id("CVE-2014-7841", "CVE-2014-8369", "CVE-2014-8884", "CVE-2014-9090");
  script_tag(name:"creation_date", value:"2014-12-07 23:00:00 +0000 (Sun, 07 Dec 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:37:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3093");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3093");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation:

CVE-2014-7841

Liu Wei of Red Hat discovered that a SCTP server doing ASCONF will panic on malformed INIT chunks by triggering a NULL pointer dereference.

CVE-2014-8369

A flaw was discovered in the way iommu mapping failures were handled in the kvm_iommu_map_pages() function in the Linux kernel. A guest OS user could exploit this flaw to cause a denial of service (host OS memory corruption) or possibly have other unspecified impact on the host OS.

CVE-2014-8884

A stack-based buffer overflow flaw was discovered in the TechnoTrend/Hauppauge DEC USB driver. A local user with write access to the corresponding device could use this flaw to crash the kernel or, potentially, elevate their privileges.

CVE-2014-9090

Andy Lutomirski discovered that the do_double_fault function in arch/x86/kernel/traps.c in the Linux kernel did not properly handle faults associated with the Stack Segment (SS) segment register, which allows local users to cause a denial of service (panic).

For the stable distribution (wheezy), these problems have been fixed in version 3.2.63-2+deb7u2. This update also includes fixes for regressions introduced by previous updates.

For the unstable distribution (sid), these problems will be fixed soon in version 3.16.7-ckt2-1.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);