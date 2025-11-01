# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703952");
  script_cve_id("CVE-2017-0663", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");
  script_tag(name:"creation_date", value:"2017-08-22 22:00:00 +0000 (Tue, 22 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-17 15:15:00 +0000 (Fri, 17 May 2019)");

  script_name("Debian: Security Advisory (DSA-3952)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3952");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3952");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-3952 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libxml2, a library providing support to read, modify and write XML and HTML files. A remote attacker could provide a specially crafted XML or HTML file that, when processed by an application using libxml2, would cause a denial-of-service against the application, information leaks, or potentially, the execution of arbitrary code with the privileges of the user running the application.

For the oldstable distribution (jessie), these problems have been fixed in version 2.9.1+dfsg1-5+deb8u5.

For the stable distribution (stretch), these problems have been fixed in version 2.9.4+dfsg1-2.2+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 2.9.4+dfsg1-3.1.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);