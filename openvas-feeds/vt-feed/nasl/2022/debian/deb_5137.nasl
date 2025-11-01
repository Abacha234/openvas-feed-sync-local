# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705137");
  script_cve_id("CVE-2022-30688");
  script_tag(name:"creation_date", value:"2022-05-18 01:00:04 +0000 (Wed, 18 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-25 18:30:00 +0000 (Wed, 25 May 2022)");

  script_name("Debian: Security Advisory (DSA-5137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5137");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5137");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/needrestart");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'needrestart' package(s) announced via the DSA-5137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered a local privilege escalation in needrestart, a utility to check which daemons need to be restarted after library upgrades. Regular expressions to detect the Perl, Python, and Ruby interpreters are not anchored, allowing a local user to escalate privileges when needrestart tries to detect if interpreters are using old source files.

For the oldstable distribution (buster), this problem has been fixed in version 3.4-5+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 3.5-4+deb11u1.

We recommend that you upgrade your needrestart packages.

For the detailed security status of needrestart please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'needrestart' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);