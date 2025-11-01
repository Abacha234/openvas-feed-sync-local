# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892753");
  script_cve_id("CVE-2021-3527", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3682", "CVE-2021-3713");
  script_tag(name:"creation_date", value:"2021-09-03 01:00:14 +0000 (Fri, 03 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)");

  script_name("Debian: Security Advisory (DLA-2753)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2753");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2753-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qemu");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-2753 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the patch for CVE-2021-3592 introduced a regression which prevented ssh connections to the host system. Since there is no imminent solution for the problem, the patch for CVE-2021-3592 has been reverted. Updated qemu packages are now available to correct this issue.

For Debian 9 stretch, this problem has been fixed in version 1:2.8+dfsg-6+deb9u16.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);