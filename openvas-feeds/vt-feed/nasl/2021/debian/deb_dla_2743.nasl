# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892743");
  script_tag(name:"creation_date", value:"2021-08-16 09:10:56 +0000 (Mon, 16 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-2743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2743");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2743-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/amd64-microcode");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'amd64-microcode' package(s) announced via the DLA-2743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DLA-2743-1 was issued for CVE-2017-5715, affecting amd64-microcode, processor microcode firmware for AMD CPUs. However, the binaries for the resulting upload weren't built and published, thereby preventing the users to upgrade to a fixed version.

For Debian 9 stretch, this problem has been fixed in version 3.20181128.1~deb9u2.

We recommend that you upgrade your amd64-microcode packages.

For the detailed security status of amd64-microcode please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'amd64-microcode' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);