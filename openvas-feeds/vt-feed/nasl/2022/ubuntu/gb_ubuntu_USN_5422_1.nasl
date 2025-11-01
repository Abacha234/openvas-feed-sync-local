# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845372");
  script_cve_id("CVE-2022-23308", "CVE-2022-29824");
  script_tag(name:"creation_date", value:"2022-05-17 01:00:32 +0000 (Tue, 17 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 14:53:00 +0000 (Tue, 10 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5422-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5422-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-5422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Shinji Sato discovered that libxml2 incorrectly handled certain XML files.
An attacker could possibly use this issue to cause a crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 14.04 ESM, and Ubuntu 16.04 ESM. (CVE-2022-23308)

It was discovered that libxml2 incorrectly handled certain XML files.
An attacker could possibly use this issue to cause a crash or execute
arbitrary code. (CVE-2022-29824)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
