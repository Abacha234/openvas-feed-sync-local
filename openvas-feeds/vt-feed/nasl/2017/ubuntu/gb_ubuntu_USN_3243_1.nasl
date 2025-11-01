# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843107");
  script_cve_id("CVE-2014-9938");
  script_tag(name:"creation_date", value:"2017-03-24 04:48:39 +0000 (Fri, 24 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 20:26:00 +0000 (Wed, 29 Apr 2020)");

  script_name("Ubuntu: Security Advisory (USN-3243-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3243-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3243-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the USN-3243-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Git incorrectly sanitized branch names in the PS1
variable when configured to display the repository status in the shell
prompt. If a user were tricked into exploring a malicious repository, a
remote attacker could use this issue to execute arbitrary code.");

  script_tag(name:"affected", value:"'git' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
