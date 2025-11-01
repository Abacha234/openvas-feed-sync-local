# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891432");
  script_cve_id("CVE-2018-13005", "CVE-2018-13006");
  script_tag(name:"creation_date", value:"2018-07-19 22:00:00 +0000 (Thu, 19 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 18:58:00 +0000 (Fri, 29 Mar 2019)");

  script_name("Debian: Security Advisory (DLA-1432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1432");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1432");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gpac' package(s) announced via the DLA-1432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two heap buffer over read conditions were found in gpac.

CVE-2018-13005

Due to an error in a while loop condition, the function urn_Read in isomedia/box_code_base.c has a heap-based buffer over-read.

CVE-2018-13006

Due to an error in a strlen call, there is a heap-based buffer over-read in the isomedia/box_dump.c function hdlr_dump.

For Debian 8 Jessie, these problems have been fixed in version 0.5.0+svn5324~dfsg1-1+deb8u1.

We recommend that you upgrade your gpac packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gpac' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);