# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843178");
  script_cve_id("CVE-2016-10249", "CVE-2016-10251", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-8654", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8882", "CVE-2016-9560", "CVE-2016-9591");
  script_tag(name:"creation_date", value:"2017-05-19 05:10:16 +0000 (Fri, 19 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 22:08:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-3295-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3295-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3295-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the USN-3295-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that JasPer incorrectly handled certain malformed
JPEG-2000 image files. If a user or automated system using JasPer were
tricked into opening a specially crafted image, an attacker could exploit
this to cause a denial of service or possibly execute code with the
privileges of the user invoking the program.");

  script_tag(name:"affected", value:"'jasper' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
