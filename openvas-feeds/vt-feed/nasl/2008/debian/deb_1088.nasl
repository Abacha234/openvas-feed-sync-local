# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56858");
  script_cve_id("CVE-2005-3863");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1088");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1088");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'centericq' package(s) announced via the DSA-1088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mehdi Oudad and Kevin Fernandez discovered a buffer overflow in the ktools library which is used in centericq, a text-mode multi-protocol instant messenger client, which may lead local or remote attackers to execute arbitrary code.

For the old stable distribution (woody) this problem has been fixed in version 4.5.1-1.1woody2.

For the stable distribution (sarge) this problem has been fixed in version 4.20.0-1sarge4.

For the unstable distribution (sid) this problem has been fixed in version 4.21.0-6.

We recommend that you upgrade your centericq package.");

  script_tag(name:"affected", value:"'centericq' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);