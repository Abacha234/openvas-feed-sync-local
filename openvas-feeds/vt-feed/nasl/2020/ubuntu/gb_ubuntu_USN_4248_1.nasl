# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844305");
  script_cve_id("CVE-2017-16545", "CVE-2017-16547", "CVE-2017-16669", "CVE-2017-17498", "CVE-2017-17500", "CVE-2017-17501", "CVE-2017-17502", "CVE-2017-17503", "CVE-2017-17782", "CVE-2017-17783");
  script_tag(name:"creation_date", value:"2020-01-23 04:00:25 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-27 21:15:00 +0000 (Mon, 27 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-4248-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4248-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4248-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the USN-4248-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GraphicsMagick incorrectly handled certain image files.
An attacker could possibly use this issue to cause a denial of service or other
unspecified impact.");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
