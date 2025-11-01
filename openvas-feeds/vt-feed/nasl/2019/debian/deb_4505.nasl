# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704505");
  script_cve_id("CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516");
  script_tag(name:"creation_date", value:"2019-08-24 02:00:13 +0000 (Sat, 24 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:36:00 +0000 (Sat, 30 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4505)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4505");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4505");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nginx");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nginx' package(s) announced via the DSA-4505 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three vulnerabilities were discovered in the HTTP/2 code of Nginx, a high-performance web and reverse proxy server, which could result in denial of service.

For the oldstable distribution (stretch), these problems have been fixed in version 1.10.3-1+deb9u3.

For the stable distribution (buster), these problems have been fixed in version 1.14.2-2+deb10u1.

We recommend that you upgrade your nginx packages.

For the detailed security status of nginx please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);