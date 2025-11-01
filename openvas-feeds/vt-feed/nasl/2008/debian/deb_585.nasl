# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53277");
  script_cve_id("CVE-2004-1001");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-585)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-585");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-585");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'shadow' package(s) announced via the DSA-585 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the shadow suite which provides programs like chfn and chsh. It is possible for a user, who is logged in but has an expired password to alter his account information with chfn or chsh without having to change the password. The problem was originally thought to be more severe.

For the stable distribution (woody) this problem has been fixed in version 20000902-12woody1.

For the unstable distribution (sid) this problem has been fixed in version 4.0.3-30.3.

We recommend that you upgrade your passwd package (from the shadow suite).");

  script_tag(name:"affected", value:"'shadow' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);