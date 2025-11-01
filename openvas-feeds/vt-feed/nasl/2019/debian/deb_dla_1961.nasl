# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891961");
  script_cve_id("CVE-2019-14464", "CVE-2019-14496", "CVE-2019-14497");
  script_tag(name:"creation_date", value:"2019-10-22 02:00:41 +0000 (Tue, 22 Oct 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-20 16:23:00 +0000 (Fri, 20 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-1961)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1961");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1961");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'milkytracker' package(s) announced via the DLA-1961 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fredric discovered a couple of buffer overflows in MilkyTracker, of which, a brief description is given below.

CVE-2019-14464

XMFile::read in XMFile.cpp in milkyplay in MilkyTracker had a heap-based buffer overflow.

CVE-2019-14496

LoaderXM::load in LoaderXM.cpp in milkyplay in MilkyTracker had a stack-based buffer overflow.

CVE-2019-14497

ModuleEditor::convertInstrument in tracker/ModuleEditor.cpp in MilkyTracker had a heap-based buffer overflow.

For Debian 8 Jessie, these problems have been fixed in version 0.90.85+dfsg-2.2+deb8u1.

We recommend that you upgrade your milkytracker packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'milkytracker' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);