# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53687");
  script_cve_id("CVE-2004-0156");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-485");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-485");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ssmtp' package(s) announced via the DSA-485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Vozeler discovered two format string vulnerabilities in ssmtp, a simple mail transport agent. Untrusted values in the functions die() and log_event() were passed to printf-like functions as format strings. These vulnerabilities could potentially be exploited by a remote mail relay to gain the privileges of the ssmtp process (including potentially root).

For the current stable distribution (woody) this problem will be fixed in version 2.50.6.1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you update your ssmtp package.");

  script_tag(name:"affected", value:"'ssmtp' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);