# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843381");
  script_cve_id("CVE-2017-1000229");
  script_tag(name:"creation_date", value:"2017-11-28 06:19:18 +0000 (Tue, 28 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-06 19:29:00 +0000 (Mon, 06 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3495-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3495-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3495-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'optipng' package(s) announced via the USN-3495-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OptiPNG incorrectly handled memory. A remote
attacker could use this issue with a specially crafted image file to cause
OptiPNG to crash, resulting in a denial of service, or possibly execute
arbitrary code.");

  script_tag(name:"affected", value:"'optipng' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
