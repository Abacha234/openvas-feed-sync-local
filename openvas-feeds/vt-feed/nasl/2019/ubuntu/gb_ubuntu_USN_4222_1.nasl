# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844278");
  script_cve_id("CVE-2017-11638", "CVE-2017-11641", "CVE-2017-11642", "CVE-2017-11643", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13134", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-13776", "CVE-2017-13777");
  script_tag(name:"creation_date", value:"2019-12-17 03:00:55 +0000 (Tue, 17 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-18 10:29:00 +0000 (Thu, 18 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-4222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4222-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4222-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the USN-4222-1 advisory.");

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
