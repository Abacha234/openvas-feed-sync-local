# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703880");
  script_cve_id("CVE-2017-9526");
  script_tag(name:"creation_date", value:"2017-06-13 22:00:00 +0000 (Tue, 13 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-16 19:29:00 +0000 (Wed, 16 Jan 2019)");

  script_name("Debian: Security Advisory (DSA-3880)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3880");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3880");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgcrypt20' package(s) announced via the DSA-3880 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a side channel attack in the EdDSA session key handling in Libgcrypt may result in information disclosure.

For the stable distribution (jessie), this problem has been fixed in version 1.6.3-2+deb8u3.

For the upcoming stable distribution (stretch), this problem has been fixed in version 1.7.6-2.

For the unstable distribution (sid), this problem has been fixed in version 1.7.6-2.

We recommend that you upgrade your libgcrypt20 packages.");

  script_tag(name:"affected", value:"'libgcrypt20' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);