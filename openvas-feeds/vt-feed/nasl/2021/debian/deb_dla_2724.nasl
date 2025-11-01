# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892724");
  script_cve_id("CVE-2019-18823");
  script_tag(name:"creation_date", value:"2021-08-02 03:00:13 +0000 (Mon, 02 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-22 13:29:00 +0000 (Fri, 22 May 2020)");

  script_name("Debian: Security Advisory (DLA-2724)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2724");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2724");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/condor");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'condor' package(s) announced via the DLA-2724 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTCondor, a distributed workload management system, has Incorrect Access Control. It is possible to use a different authentication method to submit a job than the administrator has specified. If the administrator has configured the READ or WRITE methods to include CLAIMTOBE, then it is possible to impersonate another user to the condor_schedd, for example to submit or remove jobs.

For Debian 9 stretch, this problem has been fixed in version 8.4.11~dfsg.1-1+deb9u1.

We recommend that you upgrade your condor packages.

For the detailed security status of condor please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'condor' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);