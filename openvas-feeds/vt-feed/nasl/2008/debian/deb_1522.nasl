# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60576");
  script_cve_id("CVE-2008-0888");
  script_tag(name:"creation_date", value:"2008-03-19 19:30:32 +0000 (Wed, 19 Mar 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1522)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1522");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1522");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unzip' package(s) announced via the DSA-1522 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that unzip, when processing specially crafted ZIP archives, could pass invalid pointers to the C library's free routine, potentially leading to arbitrary code execution (CVE-2008-0888).

For the old stable distribution (sarge), this problem has been fixed in version 5.52-1sarge5.

For the stable distribution (etch), this problem has been fixed in version 5.52-9etch1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your unzip package.");

  script_tag(name:"affected", value:"'unzip' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);