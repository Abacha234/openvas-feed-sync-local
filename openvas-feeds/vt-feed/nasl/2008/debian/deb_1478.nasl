# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60271");
  script_cve_id("CVE-2008-0226", "CVE-2008-0227");
  script_tag(name:"creation_date", value:"2008-01-31 18:16:52 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1478");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1478");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-1478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Luigi Auriemma discovered two buffer overflows in YaSSL, an SSL implementation included in the MySQL database package, which could lead to denial of service and possibly the execution of arbitrary code.

The old stable distribution (sarge) doesn't contain mysql-dfsg-5.0.

For the stable distribution (etch), these problems have been fixed in version 5.0.32-7etch5.

For the unstable distribution (sid), these problems have been fixed in version 5.0.51-3.

We recommend that you upgrade your mysql-dfsg-5.0 package.");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);