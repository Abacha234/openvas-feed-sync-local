# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704520");
  script_cve_id("CVE-2019-10079", "CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9518");
  script_tag(name:"creation_date", value:"2019-09-11 02:00:16 +0000 (Wed, 11 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 16:21:00 +0000 (Thu, 27 May 2021)");

  script_name("Debian: Security Advisory (DSA-4520)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4520");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4520");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/trafficserver");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'trafficserver' package(s) announced via the DSA-4520 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the HTTP/2 code of Apache Traffic Server, a reverse and forward proxy server, which could result in denial of service.

The fixes are too intrusive to backport to the version in the oldstable distribution (stretch). An upgrade to Debian stable (buster) is recommended instead.

For the stable distribution (buster), these problems have been fixed in version 8.0.2+ds-1+deb10u1.

We recommend that you upgrade your trafficserver packages.

For the detailed security status of trafficserver please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);