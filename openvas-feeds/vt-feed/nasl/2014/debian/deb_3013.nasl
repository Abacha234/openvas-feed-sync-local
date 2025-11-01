# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703013");
  script_cve_id("CVE-2014-0485");
  script_tag(name:"creation_date", value:"2014-08-26 22:00:00 +0000 (Tue, 26 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3013");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3013");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 's3ql' package(s) announced via the DSA-3013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nikolaus Rath discovered that s3ql, a file system for online data storage, used the pickle functionality of the Python programming language in an unsafe way. As a result, a malicious storage backend or man-in-the-middle attacker was able execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 1.11.1-3+deb7u1.

We recommend that you upgrade your s3ql packages.");

  script_tag(name:"affected", value:"'s3ql' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);