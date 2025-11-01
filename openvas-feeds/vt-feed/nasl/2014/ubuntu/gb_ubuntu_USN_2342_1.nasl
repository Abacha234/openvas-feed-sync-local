# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841962");
  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151", "CVE-2013-4526", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4531", "CVE-2013-4532", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2013-4540", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0182", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461", "CVE-2014-3471");
  script_tag(name:"creation_date", value:"2014-09-09 03:55:17 +0000 (Tue, 09 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 14:39:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-2342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2342-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2342-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael S. Tsirkin, Anthony Liguori, and Michael Roth discovered multiple
issues with QEMU state loading after migration. An attacker able to modify
the state data could use these issues to cause a denial of service, or
possibly execute arbitrary code. (CVE-2013-4148, CVE-2013-4149,
CVE-2013-4150, CVE-2013-4151, CVE-2013-4526, CVE-2013-4527, CVE-2013-4529,
CVE-2013-4530, CVE-2013-4531, CVE-2013-4532, CVE-2013-4533, CVE-2013-4534,
CVE-2013-4535, CVE-2013-4536, CVE-2013-4537, CVE-2013-4538, CVE-2013-4539,
CVE-2013-4540, CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182,
CVE-2014-3461)

Kevin Wolf, Stefan Hajnoczi, Fam Zheng, Jeff Cody, Stefan Hajnoczi, and
others discovered multiple issues in the QEMU block drivers. An attacker
able to modify disk images could use these issues to cause a denial of
service, or possibly execute arbitrary code. (CVE-2014-0142, CVE-2014-0143,
CVE-2014-0144, CVE-2014-0145, CVE-2014-0146, CVE-2014-0147, CVE-2014-0222,
CVE-2014-0223)

It was discovered that QEMU incorrectly handled certain PCIe bus hotplug
operations. A malicious guest could use this issue to crash the QEMU host,
resulting in a denial of service. (CVE-2014-3471)");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
