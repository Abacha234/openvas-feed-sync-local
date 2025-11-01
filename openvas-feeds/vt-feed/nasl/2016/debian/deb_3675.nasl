# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703675");
  script_cve_id("CVE-2016-10053", "CVE-2016-10054", "CVE-2016-10055", "CVE-2016-10056", "CVE-2016-10057");
  script_tag(name:"creation_date", value:"2016-09-22 22:00:00 +0000 (Thu, 22 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 19:52:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-3675)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3675");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3675");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-3675 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This updates fixes several vulnerabilities in imagemagick: Various memory handling problems and cases of missing or incomplete input sanitising may result in denial of service or the execution of arbitrary code if malformed SIXEL, PDB, MAP, SGI, TIFF and CALS files are processed.

For the stable distribution (jessie), these problems have been fixed in version 8:6.8.9.9-5+deb8u5.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);