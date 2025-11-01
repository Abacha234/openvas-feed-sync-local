# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892285");
  script_cve_id("CVE-2017-11464", "CVE-2019-20446");
  script_tag(name:"creation_date", value:"2020-07-23 03:00:17 +0000 (Thu, 23 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 22:15:00 +0000 (Tue, 28 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-2285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2285");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2285");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/librsvg");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'librsvg' package(s) announced via the DLA-2285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in librsvg, an SVG rendering library. This update corrects some denial of service issues via exponential element processing, stack exhaustion or application crash when processing specially crafted files, as well as some memory safety issues.

For Debian 9 stretch, these problems have been fixed in version 2.40.21-0+deb9u1.

We recommend that you upgrade your librsvg packages.

For the detailed security status of librsvg please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'librsvg' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);