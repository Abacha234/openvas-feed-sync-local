# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891579");
  script_cve_id("CVE-2017-17480", "CVE-2018-18088");
  script_tag(name:"creation_date", value:"2018-11-19 23:00:00 +0000 (Mon, 19 Nov 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-03 16:07:00 +0000 (Wed, 03 Feb 2021)");

  script_name("Debian: Security Advisory (DLA-1579)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1579");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1579");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg2' package(s) announced via the DLA-1579 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in openjpeg2, the open-source JPEG 2000 codec.

CVE-2017-17480

Write stack buffer overflow due to missing buffer length formatter in fscanf call (jp3d and jpwl codecs). This vulnerability might be leveraged by remote attackers using crafted jp3d and jpwl files to cause denial of service or possibly remote code execution.

CVE-2018-18088

Null pointer dereference caused by null image components in imagetopnm. This vulnerability might be leveraged by remote attackers using crafted BMP files to cause denial of service.

For Debian 8 Jessie, these problems have been fixed in version 2.1.0-2+deb8u5.

We recommend that you upgrade your openjpeg2 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);