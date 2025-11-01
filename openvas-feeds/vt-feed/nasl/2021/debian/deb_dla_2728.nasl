# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892728");
  script_cve_id("CVE-2021-25801", "CVE-2021-25802", "CVE-2021-25803", "CVE-2021-25804");
  script_tag(name:"creation_date", value:"2021-08-04 03:00:11 +0000 (Wed, 04 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-04 13:40:00 +0000 (Wed, 04 Aug 2021)");

  script_name("Debian: Security Advisory (DLA-2728)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2728");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2728");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DLA-2728 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were a number of issues in VideoLAN (aka 'vlc', a popular video and multimedia player:

CVE-2021-25801

A buffer overflow vulnerability in the __Parse_indx component allowed attackers to cause an out-of-bounds read via a crafted .avi file.

CVE-2021-25802

A buffer overflow vulnerability in the AVI_ExtractSubtitle component could have allowed attackers to cause an out-of-bounds read via a crafted .avi file.

CVE-2021-25803

A buffer overflow vulnerability in the vlc_input_attachment_New component allowed attackers to cause an out-of-bounds read via a specially-crafted .avi file.

CVE-2021-25804

A NULL-pointer dereference in 'Open' in avi.c can result in a denial of service (DoS) vulnerability.

For Debian 9 Stretch, these problems have been fixed in version 3.0.11-0+deb9u2.

We recommend that you upgrade your vlc packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);