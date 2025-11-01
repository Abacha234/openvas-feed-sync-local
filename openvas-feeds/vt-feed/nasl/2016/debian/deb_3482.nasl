# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703482");
  script_cve_id("CVE-2016-0794", "CVE-2016-0795");
  script_tag(name:"creation_date", value:"2016-02-16 23:00:00 +0000 (Tue, 16 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3482)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3482");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3482");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libreoffice' package(s) announced via the DSA-3482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An anonymous contributor working with VeriSign iDefense Labs discovered that libreoffice, a full-featured office productivity suite, did not correctly handle Lotus WordPro files. This would enable an attacker to crash the program, or execute arbitrary code, by supplying a specially crafted LWP file.

For the oldstable distribution (wheezy), these problems have been fixed in version 1:3.5.4+dfsg2-0+deb7u6.

For the stable distribution (jessie), these problems have been fixed in version 1:4.3.3-2+deb8u3.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 1:5.0.5~rc1-1.

We recommend that you upgrade your libreoffice packages.");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);