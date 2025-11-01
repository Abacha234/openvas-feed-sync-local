# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57563");
  script_cve_id("CVE-2005-4574", "CVE-2006-4805");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1201)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1201");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1201");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ethereal' package(s) announced via the DSA-1201 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Ethereal network scanner. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-4574

It was discovered that the MIME multipart dissector is vulnerable to denial of service caused by an off-by-one overflow.

CVE-2006-4805

It was discovered that the XOT dissector is vulnerable to denial of service caused by memory corruption.

For the stable distribution (sarge) these problems have been fixed in version 0.10.10-2sarge9. Due to technical problems with the security buildd infrastructure this update lacks builds for the hppa and sparc architecture. They will be released as soon as the problems are resolved.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your ethereal packages.");

  script_tag(name:"affected", value:"'ethereal' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);