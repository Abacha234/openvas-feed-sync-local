# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842105");
  script_cve_id("CVE-2014-9529", "CVE-2014-9584");
  script_tag(name:"creation_date", value:"2015-02-27 04:42:52 +0000 (Fri, 27 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2512-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2512-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-2512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was discovered in the Linux kernel's key ring. A local
user could cause a denial of service (memory corruption or panic) or
possibly have unspecified impact via the keyctl commands. (CVE-2014-9529)

A memory leak was discovered in the ISO 9660 CDROM file system when parsing
rock ridge ER records. A local user could exploit this flaw to obtain
sensitive information from kernel memory via a crafted iso9660 image.
(CVE-2014-9584)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
