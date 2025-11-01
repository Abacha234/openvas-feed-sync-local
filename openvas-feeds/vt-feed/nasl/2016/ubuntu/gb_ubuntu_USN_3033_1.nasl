# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842832");
  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5844");
  script_tag(name:"creation_date", value:"2016-07-15 03:27:24 +0000 (Fri, 15 Jul 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3033-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3033-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3033-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-3033-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that libarchive contained multiple security issues
when processing certain malformed archive files. A remote attacker could
use this issue to cause libarchive to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2015-8916, CVE-2015-8917
CVE-2015-8919, CVE-2015-8920, CVE-2015-8921, CVE-2015-8922, CVE-2015-8923,
CVE-2015-8924, CVE-2015-8925, CVE-2015-8926, CVE-2015-8928, CVE-2015-8930,
CVE-2015-8931, CVE-2015-8932, CVE-2015-8933, CVE-2015-8934, CVE-2016-5844)

Marcin 'Icewall' Noga discovered that libarchive contained multiple
security issues when processing certain malformed archive files. A remote
attacker could use this issue to cause libarchive to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2016-4300,
CVE-2016-4302)

It was discovered that libarchive incorrectly handled memory allocation
with large cpio symlinks. A remote attacker could use this issue to
possibly cause libarchive to crash, resulting in a denial of service.
(CVE-2016-4809)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
