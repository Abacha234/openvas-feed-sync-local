# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840477");
  script_cve_id("CVE-2010-2074");
  script_tag(name:"creation_date", value:"2010-08-13 12:24:53 +0000 (Fri, 13 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-967-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-967-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-967-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m' package(s) announced via the USN-967-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ludwig Nussel discovered w3m does not properly handle SSL/TLS
certificates with NULL characters in the certificate name. An
attacker could exploit this to perform a machine-in-the-middle
attack to view sensitive information or alter encrypted
communications. (CVE-2010-2074)");

  script_tag(name:"affected", value:"'w3m' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
