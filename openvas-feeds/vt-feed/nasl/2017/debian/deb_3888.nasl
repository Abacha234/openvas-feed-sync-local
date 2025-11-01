# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703888");
  script_cve_id("CVE-2017-1000369");
  script_tag(name:"creation_date", value:"2017-06-18 22:00:00 +0000 (Sun, 18 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-12 13:35:00 +0000 (Thu, 12 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3888)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3888");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3888");
  script_xref(name:"URL", value:"https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim4' package(s) announced via the DSA-3888 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Labs discovered a memory leak in the Exim mail transport agent. This is not a security vulnerability in Exim by itself, but can be used to exploit a vulnerability in stack handling. For the full details, please refer to their advisory published at: [link moved to references]

For the oldstable distribution (jessie), this problem has been fixed in version 4.84.2-2+deb8u4.

For the stable distribution (stretch), this problem has been fixed in version 4.89-2+deb9u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your exim4 packages.");

  script_tag(name:"affected", value:"'exim4' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);