# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703149");
  script_cve_id("CVE-2014-8126");
  script_tag(name:"creation_date", value:"2015-02-01 23:00:00 +0000 (Sun, 01 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 16:24:00 +0000 (Wed, 05 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-3149)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3149");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3149");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'condor' package(s) announced via the DSA-3149 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer, of Red Hat Product Security, discovered an issue in condor, a distributed workload management system. Upon job completion, it can optionally notify a user by sending an email, the mailx invocation used in that process allowed for any authenticated user able to submit jobs, to execute arbitrary code with the privileges of the condor user.

For the stable distribution (wheezy), this problem has been fixed in version 7.8.2~dfsg.1-1+deb7u3.

For the upcoming stable distribution (jessie) and unstable distribution (sid), this problem has been fixed in version 8.2.3~dfsg.1-6.

We recommend that you upgrade your condor packages.");

  script_tag(name:"affected", value:"'condor' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);