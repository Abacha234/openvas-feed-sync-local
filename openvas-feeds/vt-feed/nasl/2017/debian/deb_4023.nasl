# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704023");
  script_cve_id("CVE-2017-15566");
  script_tag(name:"creation_date", value:"2017-11-06 23:00:00 +0000 (Mon, 06 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4023");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4023");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'slurm-llnl' package(s) announced via the DSA-4023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryan Day discovered that the Simple Linux Utility for Resource Management (SLURM), a cluster resource management and job scheduling system, does not properly handle SPANK environment variables, allowing a user permitted to submit jobs to execute code as root during the Prolog or Epilog. All systems using a Prolog or Epilog script are vulnerable, regardless of whether SPANK plugins are in use.

For the stable distribution (stretch), this problem has been fixed in version 16.05.9-1+deb9u1.

For the unstable distribution (sid), this problem has been fixed in version 17.02.9-1.

We recommend that you upgrade your slurm-llnl packages.");

  script_tag(name:"affected", value:"'slurm-llnl' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);