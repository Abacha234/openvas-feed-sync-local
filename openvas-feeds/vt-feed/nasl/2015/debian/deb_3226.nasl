# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703226");
  script_cve_id("CVE-2012-6696", "CVE-2012-6697", "CVE-2015-6674");
  script_tag(name:"creation_date", value:"2015-04-14 22:00:00 +0000 (Tue, 14 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-14 12:33:00 +0000 (Mon, 14 Sep 2020)");

  script_name("Debian: Security Advisory (DSA-3226)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3226");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3226");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'inspircd' package(s) announced via the DSA-3226 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adam discovered several problems in inspircd, an IRC daemon:

An incomplete patch for CVE-2012-1836 failed to adequately resolve the problem where maliciously crafted DNS requests could lead to remote code execution through a heap-based buffer overflow.

The incorrect processing of specific DNS packets could trigger an infinite loop, thus resulting in a denial of service.

For the stable distribution (wheezy), this problem has been fixed in version 2.0.5-1+deb7u1.

For the upcoming stable distribution (jessie) and unstable distribution (sid), this problem has been fixed in version 2.0.16-1.

We recommend that you upgrade your inspircd packages.");

  script_tag(name:"affected", value:"'inspircd' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);