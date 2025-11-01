# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57381");
  script_cve_id("CVE-2006-4246");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1177)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1177");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1177");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'usermin' package(s) announced via the DSA-1177 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hendrik Weimer discovered that it is possible for a normal user to disable the login shell of the root account via usermin, a web-based administration tool.

For the stable distribution (sarge) this problem has been fixed in version 1.110-3.1.

In the upstream distribution this problem is fixed in version 1.220.

We recommend that you upgrade your usermin package.");

  script_tag(name:"affected", value:"'usermin' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);