# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841827");
  script_cve_id("CVE-2014-0107");
  script_tag(name:"creation_date", value:"2014-05-26 10:26:51 +0000 (Mon, 26 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2218-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2218-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2218-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxalan2-java' package(s) announced via the USN-2218-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicolas Gregoire discovered that Xalan-Java incorrectly handled certain
properties when the secure processing feature was enabled. An attacker
could possibly use this issue to load arbitrary classes or access external
resources.");

  script_tag(name:"affected", value:"'libxalan2-java' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
