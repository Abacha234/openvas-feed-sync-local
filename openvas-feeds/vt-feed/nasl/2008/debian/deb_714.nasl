# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53542");
  script_cve_id("CVE-2005-1046");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-714)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-714");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-714");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdelibs' package(s) announced via the DSA-714 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KDE security team discovered several vulnerabilities in the PCX and other image file format readers in the KDE core libraries, some of them exploitable to execute arbitrary code. To a small extent the packages in woody are affected as well.

For the stable distribution (woody) this problem has been fixed in version 2.2.2-13.woody.14.

For the unstable distribution (sid) this problem has been fixed in version 3.3.2-5.

We recommend that you upgrade your kdelibs packages.");

  script_tag(name:"affected", value:"'kdelibs' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);