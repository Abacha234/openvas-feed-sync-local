# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891620");
  script_cve_id("CVE-2018-19134", "CVE-2018-19478");
  script_tag(name:"creation_date", value:"2018-12-27 23:00:00 +0000 (Thu, 27 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-11 15:54:00 +0000 (Fri, 11 Jan 2019)");

  script_name("Debian: Security Advisory (DLA-1620)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1620");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1620");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ghostscript' package(s) announced via the DLA-1620 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some vulnerabilities were discovered in ghostscript, an interpreter for the PostScript language and for PDF.

CVE-2018-19134

The setpattern operator did not properly validate certain types. A specially crafted PostScript document could exploit this to crash Ghostscript or, possibly, execute arbitrary code in the context of the Ghostscript process. This is a type confusion issue because of failure to check whether the Implementation of a pattern dictionary was a structure type.

CVE-2018-19478

Attempting to open a carefully crafted PDF file results in long-running computation. A sufficiently bad page tree can lead to us taking significant amounts of time when checking the tree for recursion.

For Debian 8 Jessie, these problems have been fixed in version 9.06~dfsg-2+deb8u13.

We recommend that you upgrade your ghostscript packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);