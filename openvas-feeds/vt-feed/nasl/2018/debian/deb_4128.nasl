# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704128");
  script_cve_id("CVE-2017-5660", "CVE-2017-7671");
  script_tag(name:"creation_date", value:"2018-03-01 23:00:00 +0000 (Thu, 01 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-23 14:39:00 +0000 (Fri, 23 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-4128)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4128");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4128");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/trafficserver");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'trafficserver' package(s) announced via the DSA-4128 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Apache Traffic Server, a reverse and forward proxy server. They could lead to the use of an incorrect upstream proxy, or allow a remote attacker to cause a denial-of-service by application crash.

For the stable distribution (stretch), these problems have been fixed in version 7.0.0-6+deb9u1.

We recommend that you upgrade your trafficserver packages.

For the detailed security status of trafficserver please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);