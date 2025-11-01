# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892480");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_tag(name:"creation_date", value:"2020-12-05 04:00:17 +0000 (Sat, 05 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-30 13:48:00 +0000 (Tue, 30 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-2480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2480");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2480-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/salt");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'salt' package(s) announced via the DLA-2480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Past security updates of Salt, a remote execution manager, introduced regressions for which follow-up fixes were published:

CVE-2020-16846 regression salt-ssh master key initialization fails

CVE-2021-3197 regression Valid parameters are discarded for the SSHClient

CVE-2020-28243 follow-up Prevent argument injection in restartcheck

CVE-2021-25282 regression pillar_roots.write cannot write to subdirs

CVE-2021-25284 regression The cmd.run function crashes if passing tuple arg

For Debian 9 stretch, this problem has been fixed in version 2016.11.2+ds-1+deb9u10.

We recommend that you upgrade your salt packages.

For the detailed security status of salt please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'salt' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);