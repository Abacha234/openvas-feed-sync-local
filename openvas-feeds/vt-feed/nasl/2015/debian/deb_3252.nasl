# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703252");
  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");
  script_tag(name:"creation_date", value:"2015-05-05 22:00:00 +0000 (Tue, 05 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3252)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3252");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3252");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sqlite3' package(s) announced via the DSA-3252 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michal Zalewski discovered multiple vulnerabilities in SQLite, which may result in denial of service or the execution of arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 3.8.7.1-1+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 3.8.9-1.

For the unstable distribution (sid), these problems have been fixed in version 3.8.9-1.

We recommend that you upgrade your sqlite3 packages.");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);