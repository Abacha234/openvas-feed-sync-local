# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703443");
  script_cve_id("CVE-2015-8472", "CVE-2015-8540");
  script_tag(name:"creation_date", value:"2016-01-12 23:00:00 +0000 (Tue, 12 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-3443)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3443");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3443");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpng' package(s) announced via the DSA-3443 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the libpng PNG library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-8472

It was discovered that the original fix for CVE-2015-8126 was incomplete and did not detect a potential overrun by applications using png_set_PLTE directly. A remote attacker can take advantage of this flaw to cause a denial of service (application crash).

CVE-2015-8540

Xiao Qixue and Chen Yu discovered a flaw in the png_check_keyword function. A remote attacker can potentially take advantage of this flaw to cause a denial of service (application crash).

For the oldstable distribution (wheezy), these problems have been fixed in version 1.2.49-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 1.2.50-2+deb8u2.

We recommend that you upgrade your libpng packages.");

  script_tag(name:"affected", value:"'libpng' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);