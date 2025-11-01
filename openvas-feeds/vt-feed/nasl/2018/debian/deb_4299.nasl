# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704299");
  script_cve_id("CVE-2018-17407");
  script_tag(name:"creation_date", value:"2018-09-20 22:00:00 +0000 (Thu, 20 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-15 16:11:00 +0000 (Thu, 15 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4299)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4299");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4299");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/texlive-bin");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'texlive-bin' package(s) announced via the DSA-4299 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nick Roessler from the University of Pennsylvania has found a buffer overflow in texlive-bin, the executables for TexLive, the popular distribution of TeX document production system.

This buffer overflow can be used for arbitrary code execution by crafting a special type1 font (.pfb) and provide it to users running pdf(la)tex, dvips or luatex in a way that the font is loaded.

For the stable distribution (stretch), this problem has been fixed in version 2016.20160513.41080.dfsg-2+deb9u1.

We recommend that you upgrade your texlive-bin packages.

For the detailed security status of texlive-bin please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'texlive-bin' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);