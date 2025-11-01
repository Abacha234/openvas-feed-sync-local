# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703903");
  script_cve_id("CVE-2017-10688", "CVE-2017-9936");
  script_tag(name:"creation_date", value:"2017-07-04 22:00:00 +0000 (Tue, 04 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-22 01:29:00 +0000 (Thu, 22 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-3903)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3903");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3903");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-3903 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the libtiff library and the included tools, which may result in denial of service or the execution of arbitrary code.

For the oldstable distribution (jessie), these problems have been fixed in version 4.0.3-12.3+deb8u4.

For the stable distribution (stretch), these problems have been fixed in version 4.0.8-2+deb9u1.

For the testing distribution (buster), these problems have been fixed in version 4.0.8-3.

For the unstable distribution (sid), these problems have been fixed in version 4.0.8-3.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);