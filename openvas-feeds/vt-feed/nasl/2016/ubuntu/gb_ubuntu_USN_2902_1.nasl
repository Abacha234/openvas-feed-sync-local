# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842647");
  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");
  script_tag(name:"creation_date", value:"2016-02-18 05:23:03 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Ubuntu: Security Advisory (USN-2902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2902-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2902-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphite2' package(s) announced via the USN-2902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yves Younan discovered that graphite2 incorrectly handled certain malformed
fonts. If a user or automated system were tricked into opening a specially-
crafted font file, a remote attacker could use this issue to cause
graphite2 to crash, resulting in a denial of service, or possibly execute
arbitrary code.");

  script_tag(name:"affected", value:"'graphite2' package(s) on Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
