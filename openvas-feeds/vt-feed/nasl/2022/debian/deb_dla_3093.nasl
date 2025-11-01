# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893093");
  script_cve_id("CVE-2022-21831", "CVE-2022-22577", "CVE-2022-23633", "CVE-2022-27777");
  script_tag(name:"creation_date", value:"2022-09-04 01:00:09 +0000 (Sun, 04 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 14:57:00 +0000 (Tue, 07 Jun 2022)");

  script_name("Debian: Security Advisory (DLA-3093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3093");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3093-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/rails");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DLA-3093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The security update announced as DLA 3093-1 which included fix for CVE-2022-32224 caused a regression due to incompatibility with ruby 2.5 version. We have dropped aforementioned fix. Updated rails packages are now available.

For Debian 10 buster, this problem has been fixed in version 2:5.2.2.1+dfsg-1+deb10u5.

We recommend that you upgrade your rails packages.

For the detailed security status of rails please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);