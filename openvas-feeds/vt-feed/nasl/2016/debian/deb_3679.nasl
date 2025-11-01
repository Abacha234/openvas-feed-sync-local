# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703679");
  script_cve_id("CVE-2016-6801");
  script_tag(name:"creation_date", value:"2016-10-05 10:13:22 +0000 (Wed, 05 Oct 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-04 17:36:00 +0000 (Tue, 04 Oct 2016)");

  script_name("Debian: Security Advisory (DSA-3679)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3679");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3679");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jackrabbit' package(s) announced via the DSA-3679 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lukas Reschke discovered that Apache Jackrabbit, an implementation of the Content Repository for Java Technology API, did not correctly check the Content-Type header on HTTP POST requests, enabling Cross-Site Request Forgery (CSRF) attacks by malicious web sites.

For the stable distribution (jessie), this problem has been fixed in version 2.3.6-1+deb8u2.

For the unstable distribution (sid), this problem has been fixed in version 2.12.4-1.

We recommend that you upgrade your jackrabbit packages.");

  script_tag(name:"affected", value:"'jackrabbit' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);