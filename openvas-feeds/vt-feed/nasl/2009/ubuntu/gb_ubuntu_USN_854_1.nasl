# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66306");
  script_cve_id("CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2009-3293", "CVE-2009-3546");
  script_tag(name:"creation_date", value:"2009-11-23 19:51:51 +0000 (Mon, 23 Nov 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-854-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-854-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-854-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd2' package(s) announced via the USN-854-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tomas Hoger discovered that the GD library did not properly handle the
number of colors in certain malformed GD images. If a user or automated
system were tricked into processing a specially crafted GD image, an
attacker could cause a denial of service or possibly execute arbitrary
code. (CVE-2009-3546)

It was discovered that the GD library did not properly handle incorrect
color indexes. An attacker could send specially crafted input to
applications linked against libgd2 and cause a denial of service or
possibly execute arbitrary code. This issue only affected Ubuntu 6.06 LTS.
(CVE-2009-3293)

It was discovered that the GD library did not properly handle certain
malformed GIF images. If a user or automated system were tricked into
processing a specially crafted GIF image, an attacker could cause a denial
of service. This issue only affected Ubuntu 6.06 LTS. (CVE-2007-3475,
CVE-2007-3476)

It was discovered that the GD library did not properly handle large angle
degree values. An attacker could send specially crafted input to
applications linked against libgd2 and cause a denial of service. This
issue only affected Ubuntu 6.06 LTS. (CVE-2007-3477)");

  script_tag(name:"affected", value:"'libgd2' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
