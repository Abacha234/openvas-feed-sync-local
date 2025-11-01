# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892969");
  script_cve_id("CVE-2019-13161", "CVE-2019-18610", "CVE-2019-18790", "CVE-2019-18976", "CVE-2020-28242");
  script_tag(name:"creation_date", value:"2022-04-04 01:00:09 +0000 (Mon, 04 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-04 14:46:00 +0000 (Wed, 04 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-2969)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2969");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2969");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/asterisk");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DLA-2969 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2019-13161

Description

CVE-2019-18610

Description

CVE-2019-18790

Description

CVE-2019-18976

Description

CVE-2020-28242

Description

For Debian 9 stretch, these problems have been fixed in version 1:13.14.1~dfsg-2+deb9u6.

We recommend that you upgrade your asterisk packages.

For the detailed security status of asterisk please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);