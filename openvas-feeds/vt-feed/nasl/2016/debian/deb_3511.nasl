# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703511");
  script_cve_id("CVE-2016-1285", "CVE-2016-1286");
  script_tag(name:"creation_date", value:"2016-03-08 23:00:00 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-21 02:29:00 +0000 (Tue, 21 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3511)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3511");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3511");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-3511 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in ISC's BIND DNS server.

CVE-2016-1285

A maliciously crafted rdnc, a way to remotely administer a BIND server, operation can cause named to crash, resulting in denial of service.

CVE-2016-1286

An error parsing DNAME resource records can cause named to crash, resulting in denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 1:9.8.4.dfsg.P1-6+nmu2+deb7u10.

For the stable distribution (jessie), these problems have been fixed in version 1:9.9.5.dfsg-9+deb8u6.

For the testing (stretch) and unstable (sid) distributions, these problems will be fixed soon.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);