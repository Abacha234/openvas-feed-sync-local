# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704026");
  script_cve_id("CVE-2017-15953", "CVE-2017-15954", "CVE-2017-15955");
  script_tag(name:"creation_date", value:"2017-11-08 23:00:00 +0000 (Wed, 08 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");

  script_name("Debian: Security Advisory (DSA-4026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4026");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4026");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bchunk' package(s) announced via the DSA-4026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wen Bin discovered that bchunk, an application that converts a CD image in bin/cue format into a set of iso and cdr/wav tracks files, did not properly check its input. This would allow malicious users to crash the application or potentially execute arbitrary code.

For the oldstable distribution (jessie), these problems have been fixed in version 1.2.0-12+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 1.2.0-12+deb9u1.

We recommend that you upgrade your bchunk packages.");

  script_tag(name:"affected", value:"'bchunk' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);