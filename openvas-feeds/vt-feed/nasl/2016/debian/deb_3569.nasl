# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703569");
  script_cve_id("CVE-2015-8312", "CVE-2016-2860");
  script_tag(name:"creation_date", value:"2016-05-04 22:00:00 +0000 (Wed, 04 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-17 16:09:00 +0000 (Thu, 17 May 2018)");

  script_name("Debian: Security Advisory (DSA-3569)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3569");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3569");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-3569 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in openafs, an implementation of the distributed filesystem AFS. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-8312

Potential denial of service caused by a bug in the pioctl logic allowing a local user to overrun a kernel buffer with a single NUL byte.

CVE-2016-2860

Peter Iannucci discovered that users from foreign Kerberos realms can create groups as if they were administrators.

For the stable distribution (jessie), these problems have been fixed in version 1.6.9-2+deb8u5.

For the testing distribution (stretch), these problems have been fixed in version 1.6.17-1.

For the unstable distribution (sid), these problems have been fixed in version 1.6.17-1.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);