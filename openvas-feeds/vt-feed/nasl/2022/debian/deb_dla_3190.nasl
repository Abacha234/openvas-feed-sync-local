# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893190");
  script_cve_id("CVE-2022-2601", "CVE-2022-3775");
  script_tag(name:"creation_date", value:"2022-11-17 02:00:30 +0000 (Thu, 17 Nov 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 21:29:00 +0000 (Fri, 16 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3190");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3190-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/grub2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'grub2' package(s) announced via the DLA-3190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhang Boyang reported that the grub2 update released as DLA 3190-1 did not correctly apply fixes for CVE-2022-2601 and CVE-2022-3775. Updated packages are now available to address this issue. For reference the original advisory text follows.

Several issues were found in GRUB2's font handling code, which could result in crashes and potentially execution of arbitrary code. These could lead to by-pass of UEFI Secure Boot on affected systems.

Further, issues were found in image loading that could potentially lead to memory overflows.

For Debian 10 buster, these problems have been fixed in version 2.06-3~deb10u3.

We recommend that you upgrade your grub2 packages.

For the detailed security status of grub2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'grub2' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);