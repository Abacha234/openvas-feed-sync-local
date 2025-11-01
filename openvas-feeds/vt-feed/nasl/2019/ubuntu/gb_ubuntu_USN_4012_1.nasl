# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844046");
  script_cve_id("CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7665");
  script_tag(name:"creation_date", value:"2019-06-11 02:00:57 +0000 (Tue, 11 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 22:13:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-4012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4012-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4012-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the USN-4012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that elfutils incorrectly handled certain malformed
files. If a user or automated system were tricked into processing a
specially crafted file, elfutils could be made to crash or consume
resources, resulting in a denial of service.");

  script_tag(name:"affected", value:"'elfutils' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
