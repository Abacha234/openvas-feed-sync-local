# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56856");
  script_cve_id("CVE-2006-2542");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1086");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1086");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xmcd' package(s) announced via the DSA-1086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The xmcdconfig creates directories world-writeable allowing local users to fill the /usr and /var partition and hence cause a denial of service. This problem has been half-fixed since version 2.3-1.

For the old stable distribution (woody) this problem has been fixed in version 2.6-14woody1.

For the stable distribution (sarge) this problem has been fixed in version 2.6-17sarge1.

For the unstable distribution (sid) this problem has been fixed in version 2.6-18.

We recommend that you upgrade your xmcd package.");

  script_tag(name:"affected", value:"'xmcd' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);