# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703710");
  script_cve_id("CVE-2016-9189", "CVE-2016-9190");
  script_tag(name:"creation_date", value:"2016-11-09 23:00:00 +0000 (Wed, 09 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3710)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3710");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3710");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pillow' package(s) announced via the DSA-3710 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cris Neckar discovered multiple vulnerabilities in Pillow, a Python imaging library, which may result in the execution of arbitrary code or information disclosure if a malformed image file is processed.

For the stable distribution (jessie), these problems have been fixed in version 2.6.1-2+deb8u3.

For the testing distribution (stretch), these problems have been fixed in version 3.4.2-1.

For the unstable distribution (sid), these problems have been fixed in version 3.4.2-1.

We recommend that you upgrade your pillow packages.");

  script_tag(name:"affected", value:"'pillow' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);