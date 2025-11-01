# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891934");
  script_cve_id("CVE-2018-7588", "CVE-2018-7589", "CVE-2018-7637", "CVE-2018-7638", "CVE-2018-7639", "CVE-2018-7640", "CVE-2018-7641", "CVE-2019-1010174");
  script_tag(name:"creation_date", value:"2019-09-29 02:00:25 +0000 (Sun, 29 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 18:00:00 +0000 (Wed, 01 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-1934)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1934");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1934");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cimg' package(s) announced via the DLA-1934 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in cimg, a powerful image processing library.

CVE-2019-1010174

is related to a missing string sanitization on URLs, which might result in a command injection when loading a special crafted image.

The other CVEs are about heap-based buffer over-reads or double frees when loading an image.

For Debian 8 Jessie, these problems have been fixed in version 1.5.9+dfsg-1+deb8u1.

We recommend that you upgrade your cimg packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cimg' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);