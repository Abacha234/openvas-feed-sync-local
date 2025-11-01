# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703163");
  script_cve_id("CVE-2014-9093");
  script_tag(name:"creation_date", value:"2015-02-18 23:00:00 +0000 (Wed, 18 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3163");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3163");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libreoffice' package(s) announced via the DSA-3163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibreOffice, an office productivity suite, could try to write to invalid memory areas when importing malformed RTF files. This could allow remote attackers to cause a denial of service (crash) or arbitrary code execution via crafted RTF files.

For the stable distribution (wheezy), this problem has been fixed in version 1:3.5.4+dfsg2-0+deb7u3.

For the upcoming stable distribution (jessie), this problem has been fixed in version 1:4.3.3-2.

For the unstable distribution (sid), this problem has been fixed in version 1:4.3.3-2.

We recommend that you upgrade your libreoffice packages.");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);