# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702911");
  script_cve_id("CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"creation_date", value:"2014-04-21 22:00:00 +0000 (Mon, 21 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 18:42:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2911)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2911");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2911");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2911 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Icedove, Debian's version of the Mozilla Thunderbird mail and news client. Multiple memory safety errors, out of bound reads, use-after-frees and other implementation errors may lead to the execution of arbitrary code, information disclosure or denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 24.4.0-1~deb7u1. This updates Icedove to the Extended Support Release (ESR) branch 24. An updated and compatible version of Enigmail is included with this update.

For the testing distribution (jessie), these problems have been fixed in version 24.4.0-1.

For the unstable distribution (sid), these problems have been fixed in version 24.4.0-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);