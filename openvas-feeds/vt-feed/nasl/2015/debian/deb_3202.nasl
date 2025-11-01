# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703202");
  script_cve_id("CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");
  script_tag(name:"creation_date", value:"2015-03-21 23:00:00 +0000 (Sat, 21 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-30 19:21:00 +0000 (Tue, 30 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3202)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3202");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3202");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mono' package(s) announced via the DSA-3202 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Researchers at INRIA and Xamarin discovered several vulnerabilities in mono, a platform for running and developing applications based on the ECMA/ISO Standards. Mono's TLS stack contained several problems that hampered its capabilities: those issues could lead to client impersonation (via SKIP-TLS), SSLv2 fallback, and encryption weakening (via FREAK).

For the stable distribution (wheezy), these problems have been fixed in version 2.10.8.1-8+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 3.2.8+dfsg-10.

We recommend that you upgrade your mono packages.");

  script_tag(name:"affected", value:"'mono' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);