# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840856");
  script_cve_id("CVE-2008-3520", "CVE-2008-3522", "CVE-2009-3743", "CVE-2010-4054", "CVE-2011-4516", "CVE-2011-4517");
  script_tag(name:"creation_date", value:"2012-01-09 07:59:45 +0000 (Mon, 09 Jan 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1317-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1317-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1317-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-1317-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript did not correctly handle memory
allocation when parsing certain malformed JPEG-2000 images. If a user or
automated system were tricked into opening a specially crafted image, an
attacker could cause a denial of service and possibly execute arbitrary
code with user privileges. (CVE-2008-3520)

It was discovered that Ghostscript did not correctly handle certain
formatting operations when parsing JPEG-2000 images. If a user or automated
system were tricked into opening a specially crafted image, an attacker
could cause a denial of service and possibly execute arbitrary code with
user privileges. (CVE-2008-3522)

It was discovered that Ghostscript incorrectly handled certain malformed
TrueType fonts. If a user or automated system were tricked into opening a
document containing a specially crafted font, an attacker could cause a
denial of service and possibly execute arbitrary code with user privileges.
This issue only affected Ubuntu 8.04 LTS. (CVE-2009-3743)

It was discovered that Ghostscript incorrectly handled certain malformed
Type 2 fonts. If a user or automated system were tricked into opening a
document containing a specially crafted font, an attacker could cause a
denial of service and possibly execute arbitrary code with user privileges.
This issue only affected Ubuntu 8.04 LTS. (CVE-2010-4054)

Jonathan Foote discovered that Ghostscript incorrectly handled certain
malformed JPEG-2000 image files. If a user or automated system were tricked
into opening a specially crafted JPEG-2000 image file, an attacker could
cause Ghostscript to crash or possibly execute arbitrary code with user
privileges. (CVE-2011-4516, CVE-2011-4517)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
