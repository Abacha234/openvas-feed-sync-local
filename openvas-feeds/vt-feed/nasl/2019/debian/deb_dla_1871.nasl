# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891871");
  script_cve_id("CVE-2017-11109", "CVE-2017-17087", "CVE-2019-12735");
  script_tag(name:"creation_date", value:"2019-08-04 02:00:08 +0000 (Sun, 04 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)");

  script_name("Debian: Security Advisory (DLA-1871)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1871");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1871");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vim' package(s) announced via the DLA-1871 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several minor issues have been fixed in vim, a highly configurable text editor.

CVE-2017-11109

Vim allows attackers to cause a denial of service (invalid free) or possibly have unspecified other impact via a crafted source (aka -S) file.

CVE-2017-17087

Vim sets the group ownership of a .swp file to the editor's primary group (which may be different from the group ownership of the original file), which allows local users to obtain sensitive information by leveraging an applicable group membership.

CVE-2019-12735

Vim did not restrict the `:source!` command when executed in a sandbox.

For Debian 8 Jessie, these problems have been fixed in version 2:7.4.488-7+deb8u4.

We recommend that you upgrade your vim packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'vim' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);