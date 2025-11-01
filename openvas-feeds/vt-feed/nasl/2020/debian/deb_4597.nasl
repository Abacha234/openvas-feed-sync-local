# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704597");
  script_cve_id("CVE-2019-16869");
  script_tag(name:"creation_date", value:"2020-01-04 03:00:06 +0000 (Sat, 04 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 16:22:00 +0000 (Thu, 27 May 2021)");

  script_name("Debian: Security Advisory (DSA-4597)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4597");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4597");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/netty");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'netty' package(s) announced via the DSA-4597 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that Netty, a Java NIO client/server framework, is prone to a HTTP request smuggling vulnerability due to mishandling whitespace before the colon in HTTP headers.

For the oldstable distribution (stretch), this problem has been fixed in version 1:4.1.7-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in version 1:4.1.33-1+deb10u1.

We recommend that you upgrade your netty packages.

For the detailed security status of netty please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'netty' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);