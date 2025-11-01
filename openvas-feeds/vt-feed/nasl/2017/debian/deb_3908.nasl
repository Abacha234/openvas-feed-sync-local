# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703908");
  script_cve_id("CVE-2017-7529");
  script_tag(name:"creation_date", value:"2017-07-11 22:00:00 +0000 (Tue, 11 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:20:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-3908)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3908");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3908");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nginx' package(s) announced via the DSA-3908 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow has been found in the HTTP range module of Nginx, a high-performance web and reverse proxy server, which may result in information disclosure.

For the oldstable distribution (jessie), this problem has been fixed in version 1.6.2-5+deb8u5.

For the stable distribution (stretch), this problem has been fixed in version 1.10.3-1+deb9u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your nginx packages.");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);