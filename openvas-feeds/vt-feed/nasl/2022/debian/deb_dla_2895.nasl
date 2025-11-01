# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892895");
  script_cve_id("CVE-2021-3481", "CVE-2021-45930");
  script_tag(name:"creation_date", value:"2022-01-25 02:00:05 +0000 (Tue, 25 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-25 00:42:00 +0000 (Thu, 25 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-2895)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2895");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2895");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qt4-x11");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qt4-x11' package(s) announced via the DLA-2895 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple out-of-bounds errors were discovered in qt4-x11. The highest threat from CVE-2021-3481 (at least) is to data confidentiality the application availability.

For Debian 9 stretch, these problems have been fixed in version 4:4.8.7+dfsg-11+deb9u3.

We recommend that you upgrade your qt4-x11 packages.

For the detailed security status of qt4-x11 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);