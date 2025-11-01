# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703370");
  script_cve_id("CVE-2014-9745", "CVE-2014-9746", "CVE-2014-9747");
  script_tag(name:"creation_date", value:"2015-10-05 22:00:00 +0000 (Mon, 05 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)");

  script_name("Debian: Security Advisory (DSA-3370)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3370");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3370");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DSA-3370 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeType did not properly handle some malformed inputs. This could allow remote attackers to cause a denial of service (crash) via crafted font files.

For the oldstable distribution (wheezy), these problems have been fixed in version 2.4.9-1.1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 2.5.2-3+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 2.6-1.

For the unstable distribution (sid), these problems have been fixed in version 2.6-1.

We recommend that you upgrade your freetype packages.");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);