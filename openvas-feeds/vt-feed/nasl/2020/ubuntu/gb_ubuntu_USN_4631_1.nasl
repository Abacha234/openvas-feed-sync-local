# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844713");
  script_cve_id("CVE-2020-28241");
  script_tag(name:"creation_date", value:"2020-11-13 04:00:32 +0000 (Fri, 13 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-26 03:15:00 +0000 (Sat, 26 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4631-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4631-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4631-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmaxminddb' package(s) announced via the USN-4631-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libmaxminddb incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause
applications using libmaxminddb to crash, resulting in a denial of service.");

  script_tag(name:"affected", value:"'libmaxminddb' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
