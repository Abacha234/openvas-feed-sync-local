# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64781");
  script_cve_id("CVE-2008-1420", "CVE-2009-2663");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-825-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-825-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvorbis' package(s) announced via the USN-825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvorbis did not correctly handle certain malformed
ogg files. If a user were tricked into opening a specially crafted ogg file
with an application that uses libvorbis, an attacker could execute
arbitrary code with the user's privileges. (CVE-2009-2663)

USN-682-1 provided updated libvorbis packages to fix multiple security
vulnerabilities. The upstream security patch to fix CVE-2008-1420
introduced a regression when reading sound files encoded with libvorbis
1.0beta1. This update corrects the problem.

Original advisory details:

 It was discovered that libvorbis did not correctly handle certain
 malformed sound files. If a user were tricked into opening a specially
 crafted sound file with an application that uses libvorbis, an attacker
 could execute arbitrary code with the user's privileges. (CVE-2008-1420)");

  script_tag(name:"affected", value:"'libvorbis' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
