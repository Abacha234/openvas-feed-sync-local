# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71350");
  script_cve_id("CVE-2012-0208");
  script_tag(name:"creation_date", value:"2012-05-31 15:44:54 +0000 (Thu, 31 May 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2472)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2472");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2472");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gridengine' package(s) announced via the DSA-2472 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dave Love discovered that users who are allowed to submit jobs to a Grid Engine installation can escalate their privileges to root because the environment is not properly sanitized before creating processes.

For the stable distribution (squeeze), this problem has been fixed in version 6.2u5-1squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 6.2u5-6.

We recommend that you upgrade your gridengine packages.");

  script_tag(name:"affected", value:"'gridengine' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);