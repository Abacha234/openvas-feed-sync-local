# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703630");
  script_cve_id("CVE-2016-6207");
  script_tag(name:"creation_date", value:"2016-08-02 05:26:59 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:04:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-3630)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3630");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3630");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgd2' package(s) announced via the DSA-3630 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Secunia Research at Flexera Software discovered an integer overflow vulnerability within the _gdContributionsAlloc() function in libgd2, a library for programmatic graphics creation and manipulation. A remote attacker can take advantage of this flaw to cause a denial-of-service against an application using the libgd2 library.

For the stable distribution (jessie), this problem has been fixed in version 2.1.0-5+deb8u6.

For the unstable distribution (sid), this problem has been fixed in version 2.2.2-43-g22cba39-1.

We recommend that you upgrade your libgd2 packages.");

  script_tag(name:"affected", value:"'libgd2' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);