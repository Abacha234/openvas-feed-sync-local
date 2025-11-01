# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704657");
  script_cve_id("CVE-2020-5260");
  script_tag(name:"creation_date", value:"2020-04-15 03:00:05 +0000 (Wed, 15 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-19 18:21:00 +0000 (Fri, 19 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4657)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4657");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4657");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/git");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git' package(s) announced via the DSA-4657 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm of Google Project Zero discovered a flaw in git, a fast, scalable, distributed revision control system. With a crafted URL that contains a newline, the credential helper machinery can be fooled to return credential information for a wrong host.

For the oldstable distribution (stretch), this problem has been fixed in version 1:2.11.0-3+deb9u6.

For the stable distribution (buster), this problem has been fixed in version 1:2.20.1-2+deb10u2.

We recommend that you upgrade your git packages.

For the detailed security status of git please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'git' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);