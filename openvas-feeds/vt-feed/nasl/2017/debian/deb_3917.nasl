# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703917");
  script_cve_id("CVE-2017-11110");
  script_tag(name:"creation_date", value:"2017-07-22 22:00:00 +0000 (Sat, 22 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3917)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3917");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3917");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'catdoc' package(s) announced via the DSA-3917 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer underflow flaw was discovered in catdoc, a text extractor for MS-Office files, which may lead to denial of service (application crash) or have unspecified other impact, if a specially crafted file is processed.

For the oldstable distribution (jessie), this problem has been fixed in version 0.94.4-1.1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 1:0.94.3~git20160113.dbc9ec6+dfsg-1+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 1:0.95-3.

For the unstable distribution (sid), this problem has been fixed in version 1:0.95-3.

We recommend that you upgrade your catdoc packages.");

  script_tag(name:"affected", value:"'catdoc' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);