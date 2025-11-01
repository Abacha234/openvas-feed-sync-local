# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703571");
  script_cve_id("CVE-2016-4561");
  script_tag(name:"creation_date", value:"2016-05-07 22:00:00 +0000 (Sat, 07 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-16 13:59:00 +0000 (Mon, 16 May 2016)");

  script_name("Debian: Security Advisory (DSA-3571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3571");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3571");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ikiwiki' package(s) announced via the DSA-3571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon McVittie discovered a cross-site scripting vulnerability in the error reporting of Ikiwiki, a wiki compiler. This update also hardens ikiwiki's use of imagemagick in the img plugin.

For the stable distribution (jessie), this problem has been fixed in version 3.20141016.3.

For the unstable distribution (sid), this problem has been fixed in version 3.20160506.

We recommend that you upgrade your ikiwiki packages.");

  script_tag(name:"affected", value:"'ikiwiki' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);