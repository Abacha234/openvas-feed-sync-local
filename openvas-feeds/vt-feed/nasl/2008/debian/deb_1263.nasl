# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58118");
  script_cve_id("CVE-2007-0897", "CVE-2007-0898", "CVE-2007-0899");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1263");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1263");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Clam anti-virus toolkit, which may lead to denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-0897

It was discovered that malformed CAB archives may exhaust file descriptors, which allows denial of service.

CVE-2007-0898

It was discovered that a directory traversal vulnerability in the MIME header parser may lead to denial of service.

For the stable distribution (sarge) these problems have been fixed in version 0.84-2.sarge.15.

For the upcoming stable distribution (etch) these problems have been fixed in version 0.88.7-2.

For the unstable distribution (sid) these problems have been fixed in version 0.90-1.

We recommend that you upgrade your clamav packages.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);