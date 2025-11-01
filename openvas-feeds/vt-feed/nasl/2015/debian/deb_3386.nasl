# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703386");
  script_cve_id("CVE-2015-7696", "CVE-2015-7697");
  script_tag(name:"creation_date", value:"2015-10-30 23:00:00 +0000 (Fri, 30 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3386)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3386");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3386");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unzip' package(s) announced via the DSA-3386 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been found in unzip, a de-archiver for .zip files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-7696

Gustavo Grieco discovered that unzip incorrectly handled certain password protected archives. If a user or automated system were tricked into processing a specially crafted zip archive, an attacker could possibly execute arbitrary code.

CVE-2015-7697

Gustavo Grieco discovered that unzip incorrectly handled certain malformed archives. If a user or automated system were tricked into processing a specially crafted zip archive, an attacker could possibly cause unzip to hang, resulting in a denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 6.0-8+deb7u4.

For the stable distribution (jessie), these problems have been fixed in version 6.0-16+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 6.0-19.

For the unstable distribution (sid), these problems have been fixed in version 6.0-19.

We recommend that you upgrade your unzip packages.");

  script_tag(name:"affected", value:"'unzip' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);