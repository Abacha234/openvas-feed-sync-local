# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841287");
  script_cve_id("CVE-2012-4461", "CVE-2012-4530", "CVE-2012-5532");
  script_tag(name:"creation_date", value:"2013-01-21 04:21:17 +0000 (Mon, 21 Jan 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1699-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1699-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jon Howell reported a flaw in the Linux kernel's KVM (Kernel-based virtual
machine) subsystem's handling of the XSAVE feature. On hosts, using qemu
userspace, without the XSAVE feature an unprivileged local attacker could
exploit this flaw to crash the system. (CVE-2012-4461)

A flaw was discovered in the Linux kernel's handling of script execution
when module loading is enabled. A local attacker could exploit this flaw to
cause a leak of kernel stack contents. (CVE-2012-4530)

Florian Weimer discovered that hypervkvpd, which is distributed in the
Linux kernel, was not correctly validating source addresses of netlink
packets. An untrusted local user can cause a denial of service by causing
hypervkvpd to exit. (CVE-2012-5532)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
