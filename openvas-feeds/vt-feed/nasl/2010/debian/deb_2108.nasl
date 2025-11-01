# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68090");
  script_cve_id("CVE-2010-1326");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2108)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2108");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2108");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cvsnt' package(s) announced via the DSA-2108 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that in cvsnt, a multi-platform version of the original source code versioning system CVS, an error in the authentication code allows a malicious, unprivileged user, through the use of a specially crafted branch name, to gain write access to any module or directory, including CVSROOT itself. The attacker can then execute arbitrary code as root by modifying or adding administrative scripts in that directory.

For the stable distribution (lenny), this problem has been fixed in version 2.5.03.2382-3.3+lenny1.

We recommend that you upgrade your cvsnt package.");

  script_tag(name:"affected", value:"'cvsnt' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);