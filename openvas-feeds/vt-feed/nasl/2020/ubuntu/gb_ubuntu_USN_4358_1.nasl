# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844430");
  script_cve_id("CVE-2018-20030", "CVE-2020-12767");
  script_tag(name:"creation_date", value:"2020-05-14 03:00:30 +0000 (Thu, 14 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-11 15:15:00 +0000 (Thu, 11 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-4358-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4358-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4358-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libexif' package(s) announced via the USN-4358-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libexif incorrectly handled certain tags.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2018-20030)

It was discovered that libexif incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a crash.
(CVE-2020-12767)");

  script_tag(name:"affected", value:"'libexif' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
