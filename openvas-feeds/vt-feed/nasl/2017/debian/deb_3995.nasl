# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703995");
  script_cve_id("CVE-2017-13720", "CVE-2017-13722");
  script_tag(name:"creation_date", value:"2017-10-09 22:00:00 +0000 (Mon, 09 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-13 02:29:00 +0000 (Mon, 13 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3995)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3995");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3995");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxfont' package(s) announced via the DSA-3995 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in libXfont, the X11 font rasterisation library, which could result in denial of service or memory disclosure.

For the oldstable distribution (jessie), these problems have been fixed in version 1:1.5.1-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 1:2.0.1-3+deb9u1.

We recommend that you upgrade your libxfont packages.");

  script_tag(name:"affected", value:"'libxfont' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);