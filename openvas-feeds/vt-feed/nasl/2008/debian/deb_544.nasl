# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53234");
  script_cve_id("CVE-2004-0559");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-544)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-544");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-544");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webmin' package(s) announced via the DSA-544 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ludwig Nussel discovered a problem in webmin, a web-based administration toolkit. A temporary directory was used but without checking for the previous owner. This could allow an attacker to create the directory and place dangerous symbolic links inside.

For the stable distribution (woody) this problem has been fixed in version 0.94-7woody3.

For the unstable distribution (sid) this problem has been fixed in version 1.160-1 of webmin and 1.090-1 of usermin.

We recommend that you upgrade your webmin packages.");

  script_tag(name:"affected", value:"'webmin' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);