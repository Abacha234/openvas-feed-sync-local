# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703633");
  script_cve_id("CVE-2015-8338", "CVE-2016-4480", "CVE-2016-4962", "CVE-2016-5242", "CVE-2016-6258");
  script_tag(name:"creation_date", value:"2016-08-02 05:25:39 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3633)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3633");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3633");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3633 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-8338

Julien Grall discovered that Xen on ARM was susceptible to denial of service via long running memory operations.

CVE-2016-4480

Jan Beulich discovered that incorrect page table handling could result in privilege escalation inside a Xen guest instance.

CVE-2016-4962

Wei Liu discovered multiple cases of missing input sanitising in libxl which could result in denial of service.

CVE-2016-5242

Aaron Cornelius discovered that incorrect resource handling on ARM systems could result in denial of service.

CVE-2016-6258

Jeremie Boutoille discovered that incorrect pagetable handling in PV instances could result in guest to host privilege escalation.

For the stable distribution (jessie), these problems have been fixed in version 4.4.1-9+deb8u6.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);