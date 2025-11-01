# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892292");
  script_cve_id("CVE-2019-14464", "CVE-2019-14496", "CVE-2019-14497", "CVE-2020-15569");
  script_tag(name:"creation_date", value:"2020-07-28 03:00:12 +0000 (Tue, 28 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-20 16:23:00 +0000 (Fri, 20 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-2292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2292");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2292");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/milkytracker");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'milkytracker' package(s) announced via the DLA-2292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2019-14464

Heap-based buffer overflow in XMFile::read

CVE-2019-14496

Stack-based buffer overflow in LoaderXM::load

CVE-2019-14497

Heap-based buffer overflow in ModuleEditor::convertInstrument

CVE-2020-15569

Use-after-free in the PlayerGeneric destructor

For Debian 9 stretch, these problems have been fixed in version 0.90.86+dfsg-2+deb9u1.

We recommend that you upgrade your milkytracker packages.

For the detailed security status of milkytracker please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'milkytracker' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);