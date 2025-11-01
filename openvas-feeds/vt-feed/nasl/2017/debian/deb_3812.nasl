# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703812");
  script_cve_id("CVE-2017-6903");
  script_tag(name:"creation_date", value:"2017-03-17 23:00:00 +0000 (Fri, 17 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3812)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3812");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3812");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ioquake3' package(s) announced via the DSA-3812 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ioquake3, a modified version of the ioQuake3 game engine performs insufficient restrictions on automatically downloaded content (pk3 files or game code), which allows malicious game servers to modify configuration settings including driver settings.

For the stable distribution (jessie), this problem has been fixed in version 1.36+u20140802+gca9eebb-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1.36+u20161101+dfsg1-2.

We recommend that you upgrade your ioquake3 packages.");

  script_tag(name:"affected", value:"'ioquake3' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);