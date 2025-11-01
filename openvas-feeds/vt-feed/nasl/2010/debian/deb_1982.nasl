# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66804");
  script_cve_id("CVE-2010-0303");
  script_tag(name:"creation_date", value:"2010-02-10 20:51:26 +0000 (Wed, 10 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1982)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1982");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1982");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hybserv' package(s) announced via the DSA-1982 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Julien Cristau discovered that hybserv, a daemon running IRC services for IRCD-Hybrid, is prone to a denial of service attack via the commands option.

For the stable distribution (lenny), this problem has been fixed in version 1.9.2-4+lenny2.

Due to a bug in the archive system, it is not possible to release the fix for the oldstable distribution (etch) simultaneously. Therefore, etch will be fixed in version 1.9.2-4+etch1 as soon as it becomes available.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.9.2-4.1.

We recommend that you upgrade your hybserv packages.");

  script_tag(name:"affected", value:"'hybserv' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);