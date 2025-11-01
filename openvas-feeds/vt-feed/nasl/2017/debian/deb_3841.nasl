# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703841");
  script_cve_id("CVE-2017-7957");
  script_tag(name:"creation_date", value:"2017-05-01 22:00:00 +0000 (Mon, 01 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 17:15:00 +0000 (Tue, 26 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3841)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3841");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3841");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxstream-java' package(s) announced via the DSA-3841 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that XStream, a Java library to serialise objects to XML and back again, was suspectible to denial of service during unmarshalling.

For the stable distribution (jessie), this problem has been fixed in version 1.4.7-2+deb8u2.

For the upcoming stable distribution (stretch), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.4.9-2.

We recommend that you upgrade your libxstream-java packages.");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);