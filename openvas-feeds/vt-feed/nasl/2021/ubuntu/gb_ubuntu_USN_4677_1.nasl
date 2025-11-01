# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844769");
  script_cve_id("CVE-2020-29361", "CVE-2020-29362", "CVE-2020-29363");
  script_tag(name:"creation_date", value:"2021-01-11 10:57:26 +0000 (Mon, 11 Jan 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 19:50:00 +0000 (Thu, 07 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4677-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4677-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4677-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p11-kit' package(s) announced via the USN-4677-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Cook discovered that p11-kit incorrectly handled certain memory
operations. An attacker could use this issue to cause p11-kit to crash,
resulting in a denial of service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'p11-kit' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
