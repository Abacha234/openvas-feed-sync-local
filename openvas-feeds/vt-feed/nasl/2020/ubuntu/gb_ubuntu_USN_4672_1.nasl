# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844762");
  script_cve_id("CVE-2014-9913", "CVE-2016-9844", "CVE-2018-1000035", "CVE-2018-18384", "CVE-2019-13232");
  script_tag(name:"creation_date", value:"2020-12-17 04:00:45 +0000 (Thu, 17 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4672-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4672-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4672-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the USN-4672-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rene Freingruber discovered that unzip incorrectly handled certain
specially crafted password protected ZIP archives. If a user or automated
system using unzip were tricked into opening a specially crafted zip file,
an attacker could exploit this to cause a crash, resulting in a denial of
service. (CVE-2018-1000035)

Antonio Carista discovered that unzip incorrectly handled certain
specially crafted ZIP archives. If a user or automated system using unzip
were tricked into opening a specially crafted zip file, an attacker could
exploit this to cause a crash, resulting in a denial of service. This
issue only affected Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.
(CVE-2018-18384)

It was discovered that unzip incorrectly handled certain specially crafted
ZIP archives. If a user or automated system using unzip were tricked into
opening a specially crafted zip file, an attacker could exploit this to
cause resource consumption, resulting in a denial of service.
(CVE-2019-13232)

Martin Carpenter discovered that unzip incorrectly handled certain
specially crafted ZIP archives. If a user or automated system using unzip
were tricked into opening a specially crafted zip file, an attacker could
exploit this to cause a crash, resulting in a denial of service. This
issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04
LTS. (CVE-2014-9913)

Alexis Vanden Eijnde discovered that unzip incorrectly handled certain
specially crafted ZIP archives. If a user or automated system using unzip
were tricked into opening a specially crafted zip file, an attacker could
exploit this to cause a crash, resulting in a denial of service. This
issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04
LTS. (CVE-2016-9844)");

  script_tag(name:"affected", value:"'unzip' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
