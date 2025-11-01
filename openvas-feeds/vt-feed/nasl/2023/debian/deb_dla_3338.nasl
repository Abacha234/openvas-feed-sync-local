# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893338");
  script_cve_id("CVE-2023-22490", "CVE-2023-23946");
  script_tag(name:"creation_date", value:"2023-02-24 02:00:09 +0000 (Fri, 24 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 19:59:00 +0000 (Thu, 23 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3338)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3338");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3338");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/git");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git' package(s) announced via the DLA-3338 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in git, a fast, scalable and distributed revision control system.

CVE-2023-22490

yvvdwf found a data exfiltration vulnerability while performing a local clone from a malicious repository even using a non-local transport.

CVE-2023-23946

Joern Schneeweisz found a path traversal vulnerability in git-apply that a path outside the working tree can be overwritten as the acting user.

For Debian 10 buster, these problems have been fixed in version 1:2.20.1-2+deb10u8.

We recommend that you upgrade your git packages.

For the detailed security status of git please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'git' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);