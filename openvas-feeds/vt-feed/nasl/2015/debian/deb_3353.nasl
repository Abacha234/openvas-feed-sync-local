# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703353");
  script_cve_id("CVE-2015-5177");
  script_tag(name:"creation_date", value:"2015-09-04 22:00:00 +0000 (Fri, 04 Sep 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 13:01:00 +0000 (Tue, 07 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3353)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3353");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3353");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openslp-dfsg' package(s) announced via the DSA-3353 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qinghao Tang of QIHU 360 discovered a double free flaw in OpenSLP, an implementation of the IETF Service Location Protocol. This could allow remote attackers to cause a denial of service (crash).

For the oldstable distribution (wheezy), this problem has been fixed in version 1.2.1-9+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 1.2.1-10+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1.2.1-11.

We recommend that you upgrade your openslp-dfsg packages.");

  script_tag(name:"affected", value:"'openslp-dfsg' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);