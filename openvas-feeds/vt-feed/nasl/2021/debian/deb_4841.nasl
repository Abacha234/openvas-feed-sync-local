# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704841");
  script_cve_id("CVE-2019-19728", "CVE-2020-12693", "CVE-2020-27745", "CVE-2020-27746");
  script_tag(name:"creation_date", value:"2021-01-29 04:00:11 +0000 (Fri, 29 Jan 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-28 17:48:00 +0000 (Thu, 28 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4841)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4841");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4841");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/slurm-llnl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'slurm-llnl' package(s) announced via the DSA-4841 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the Simple Linux Utility for Resource Management (SLURM), a cluster resource management and job scheduling system, which could result in denial of service, information disclosure or privilege escalation.

For the stable distribution (buster), these problems have been fixed in version 18.08.5.2-1+deb10u2.

We recommend that you upgrade your slurm-llnl packages.

For the detailed security status of slurm-llnl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'slurm-llnl' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);