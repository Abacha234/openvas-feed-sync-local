# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703958");
  script_cve_id("CVE-2017-11568", "CVE-2017-11569", "CVE-2017-11571", "CVE-2017-11572", "CVE-2017-11574", "CVE-2017-11575", "CVE-2017-11576", "CVE-2017-11577");
  script_tag(name:"creation_date", value:"2017-08-28 22:00:00 +0000 (Mon, 28 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 14:23:00 +0000 (Mon, 13 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3958)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3958");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3958");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fontforge' package(s) announced via the DSA-3958 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FontForge, a font editor, did not correctly validate its input. An attacker could use this flaw by tricking a user into opening a maliciously crafted OpenType font file, thus causing a denial-of-service via application crash, or execution of arbitrary code.

For the oldstable distribution (jessie), these problems have been fixed in version 20120731.b-5+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 1:20161005~dfsg-4+deb9u1.

We recommend that you upgrade your fontforge packages.");

  script_tag(name:"affected", value:"'fontforge' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);