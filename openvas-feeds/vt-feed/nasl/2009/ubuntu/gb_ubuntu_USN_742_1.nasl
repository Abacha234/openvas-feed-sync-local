# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63698");
  script_cve_id("CVE-2008-3520", "CVE-2008-3521", "CVE-2008-3522");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-742-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-742-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-742-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the USN-742-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that JasPer did not correctly handle memory allocation
when parsing certain malformed JPEG2000 images. If a user were tricked into
opening a specially crafted image with an application that uses libjasper,
an attacker could cause a denial of service and possibly execute arbitrary
code with the user's privileges. (CVE-2008-3520)

It was discovered that JasPer created temporary files in an insecure way.
Local users could exploit a race condition and cause a denial of service in
libjasper applications.
(CVE-2008-3521)

It was discovered that JasPer did not correctly handle certain formatting
operations. If a user were tricked into opening a specially crafted image
with an application that uses libjasper, an attacker could cause a denial
of service and possibly execute arbitrary code with the user's privileges.
(CVE-2008-3522)");

  script_tag(name:"affected", value:"'jasper' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
