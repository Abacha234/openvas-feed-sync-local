# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703526");
  script_cve_id("CVE-2015-8792");
  script_tag(name:"creation_date", value:"2016-03-22 23:00:00 +0000 (Tue, 22 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3526)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3526");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3526");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmatroska' package(s) announced via the DSA-3526 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libmatroska, an extensible open standard audio/video container format, incorrectly processed EBML lacing. By providing maliciously crafted input, an attacker could use this flaw to force some leakage of information located in the process heap memory.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.3.0-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 1.4.1-2+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this problem has been fixed in version 1.4.4-1.

We recommend that you upgrade your libmatroska packages.");

  script_tag(name:"affected", value:"'libmatroska' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);