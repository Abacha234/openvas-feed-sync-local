# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892836");
  script_cve_id("CVE-2021-43527");
  script_tag(name:"creation_date", value:"2021-12-03 02:00:08 +0000 (Fri, 03 Dec 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 14:32:00 +0000 (Thu, 16 Dec 2021)");

  script_name("Debian: Security Advisory (DLA-2836)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2836");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2836-2");
  script_xref(name:"URL", value:"https://bugs.debian.org/1001219");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nss");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DLA-2836 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DLA-2836-1 was rolled out, fixing CVE-2021-43527 in nss, but that lead to a regression, preventing SSL connections in Chromium. The complete bug report could be found here: [link moved to references].

For Debian 9 stretch, this problem has been fixed in version 2:3.26.2-1.1+deb9u4.

We recommend that you upgrade your nss packages.

For the detailed security status of nss please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);