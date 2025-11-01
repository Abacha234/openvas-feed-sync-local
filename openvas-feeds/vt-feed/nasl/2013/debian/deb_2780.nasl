# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702780");
  script_cve_id("CVE-2012-0553", "CVE-2012-0572", "CVE-2012-0574", "CVE-2012-1702", "CVE-2012-1705", "CVE-2012-2750", "CVE-2012-5060", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0389", "CVE-2013-1492", "CVE-2013-1506", "CVE-2013-1521", "CVE-2013-1531", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1555", "CVE-2013-1623", "CVE-2013-1861", "CVE-2013-2375", "CVE-2013-2378", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3808", "CVE-2013-3839");
  script_tag(name:"creation_date", value:"2013-10-17 22:00:00 +0000 (Thu, 17 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:22:00 +0000 (Tue, 19 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-2780)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2780");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2780");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.1' package(s) announced via the DSA-2780 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This DSA updates the MySQL database to 5.1.72. This fixes multiple unspecified security problems in the Optimizer component: [link moved to references]

For the oldstable distribution (squeeze), these problems have been fixed in version 5.1.72-2.

We recommend that you upgrade your mysql-5.1 packages.");

  script_tag(name:"affected", value:"'mysql-5.1' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);