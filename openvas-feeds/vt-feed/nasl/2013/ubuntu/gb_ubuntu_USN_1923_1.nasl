# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841526");
  script_cve_id("CVE-2013-4242");
  script_tag(name:"creation_date", value:"2013-08-08 06:18:18 +0000 (Thu, 08 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1923-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1923-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg, libgcrypt11' package(s) announced via the USN-1923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yuval Yarom and Katrina Falkner discovered a timing-based information leak,
known as Flush+Reload, that could be used to trace execution in programs.
GnuPG and Libgcrypt followed different execution paths based on key-related
data, which could be used to expose the contents of private keys.");

  script_tag(name:"affected", value:"'gnupg, libgcrypt11' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
