# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704052");
  script_cve_id("CVE-2017-14176");
  script_tag(name:"creation_date", value:"2017-11-28 23:00:00 +0000 (Tue, 28 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4052");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4052");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bzr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bzr' package(s) announced via the DSA-4052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adam Collard discovered that Bazaar, an easy to use distributed version control system, did not correctly handle maliciously constructed bzr+ssh URLs, allowing a remote attacker to run an arbitrary shell command.

For the oldstable distribution (jessie), this problem has been fixed in version 2.6.0+bzr6595-6+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 2.7.0+bzr6619-7+deb9u1.

We recommend that you upgrade your bzr packages.

For the detailed security status of bzr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bzr' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);