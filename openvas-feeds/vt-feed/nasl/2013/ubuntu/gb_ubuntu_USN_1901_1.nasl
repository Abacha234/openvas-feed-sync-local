# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841501");
  script_cve_id("CVE-2012-0037");
  script_tag(name:"creation_date", value:"2013-07-09 10:21:04 +0000 (Tue, 09 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1901-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1901-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1901-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'raptor2' package(s) announced via the USN-1901-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timothy D. Morgan discovered that Raptor would unconditionally load XML
external entities. If a user were tricked into opening a specially crafted
document in an application linked against Raptor, an attacker could
possibly obtain access to arbitrary files on the user's system or
potentially execute arbitrary code with the privileges of the user invoking
the program.");

  script_tag(name:"affected", value:"'raptor2' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
