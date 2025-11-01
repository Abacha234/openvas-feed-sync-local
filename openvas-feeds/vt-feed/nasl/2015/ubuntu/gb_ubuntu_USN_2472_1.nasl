# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842068");
  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141");
  script_tag(name:"creation_date", value:"2015-01-23 11:59:13 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 21:26:00 +0000 (Wed, 05 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-2472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2472-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2472-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the USN-2472-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wolfgang Ettlinger discovered that unzip incorrectly handled certain
malformed zip archives. If a user or automated system were tricked into
processing a specially crafted zip archive, an attacker could possibly
execute arbitrary code.");

  script_tag(name:"affected", value:"'unzip' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
