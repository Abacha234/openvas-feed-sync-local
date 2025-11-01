# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840430");
  script_cve_id("CVE-2009-1284", "CVE-2010-0739", "CVE-2010-0827", "CVE-2010-1440");
  script_tag(name:"creation_date", value:"2010-05-07 13:42:01 +0000 (Fri, 07 May 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-937-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-937-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-bin' package(s) announced via the USN-937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that TeX Live incorrectly handled certain long .bib
bibliography files. If a user or automated system were tricked into
processing a specially crafted bib file, an attacker could cause a denial
of service via application crash. This issue only affected Ubuntu 8.04 LTS,
9.04 and 9.10. (CVE-2009-1284)

Marc Schoenefeld, Karel Srot and Ludwig Nussel discovered that TeX Live
incorrectly handled certain malformed dvi files. If a user or automated
system were tricked into processing a specially crafted dvi file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2010-0739, CVE-2010-1440)

Dan Rosenberg discovered that TeX Live incorrectly handled certain
malformed dvi files. If a user or automated system were tricked into
processing a specially crafted dvi file, an attacker could cause a denial
of service via application crash, or possibly execute arbitrary code with
the privileges of the user invoking the program. (CVE-2010-0827)");

  script_tag(name:"affected", value:"'texlive-bin' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
