# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892064");
  script_cve_id("CVE-2019-20373");
  script_tag(name:"creation_date", value:"2020-01-11 04:00:26 +0000 (Sat, 11 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-24 15:11:00 +0000 (Fri, 24 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-2064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2064");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2064");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldm' package(s) announced via the DLA-2064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a hook script of ldm, the display manager for the Linux Terminal Server Project incorrectly parsed responses from an SSH server which could result in local root privilege escalation.

CVE-2019-20373

LTSP LDM through 2.18.06 allows fat-client root access because the LDM_USERNAME variable may have an empty value if the user's shell lacks support for Bourne shell syntax. This is related to a run-x-session script.

For Debian 8 Jessie, these problems have been fixed in version 2:2.2.15-2+deb8u1.

We recommend that you upgrade your ldm packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ldm' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);