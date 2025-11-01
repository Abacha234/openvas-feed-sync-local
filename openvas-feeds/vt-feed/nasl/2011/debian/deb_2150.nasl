# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68988");
  script_cve_id("CVE-2011-0009");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2150");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2150");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker3.6' package(s) announced via the DSA-2150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Request Tracker, an issue tracking system, stored passwords in its database by using an insufficiently strong hashing method. If an attacker would have access to the password database, he could decode the passwords stored in it.

For the stable distribution (lenny), this problem has been fixed in version 3.6.7-5+lenny5.

The testing distribution (squeeze) will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 3.8.8-7 of the request-tracker3.8 package.

We recommend that you upgrade your Request Tracker packages.");

  script_tag(name:"affected", value:"'request-tracker3.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);