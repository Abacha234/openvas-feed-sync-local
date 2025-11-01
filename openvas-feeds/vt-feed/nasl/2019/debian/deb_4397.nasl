# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704397");
  script_cve_id("CVE-2019-3824");
  script_tag(name:"creation_date", value:"2019-02-27 23:00:00 +0000 (Wed, 27 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4397)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4397");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4397");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ldb");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldb' package(s) announced via the DSA-4397 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Garming Sam reported an out-of-bounds read in the ldb_wildcard_compare() function of ldb, a LDAP-like embedded database, resulting in denial of service.

For the stable distribution (stretch), this problem has been fixed in version 2:1.1.27-1+deb9u1.

We recommend that you upgrade your ldb packages.

For the detailed security status of ldb please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ldb' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);