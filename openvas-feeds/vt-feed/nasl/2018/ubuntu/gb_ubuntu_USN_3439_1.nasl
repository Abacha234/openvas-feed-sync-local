# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843791");
  script_cve_id("CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064");
  script_tag(name:"creation_date", value:"2018-10-26 04:20:37 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-13 18:48:00 +0000 (Mon, 13 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3439-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3439-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3439-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1' package(s) announced via the USN-3439-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a buffer overrun.
(CVE-2017-0898)

Yusuke Endoh discovered that Ruby incorrectly handled certain files.
An attacker could use this to execute terminal escape sequences.
(CVE-2017-0899)

Yusuke Endoh discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a denial of service.
(CVE-2017-0900)

It was discovered that Ruby incorrectly handled certain files.
An attacker could use this to overwrite any file on the filesystem.
(CVE-2017-0901)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to execute arbitrary code.
(CVE-2017-10784)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a denial of service.
(CVE-2017-14033)

It was discovered that Ruby incorrectly handled certain files.
An attacker could use this to expose sensitive information.
(CVE-2017-14064)");

  script_tag(name:"affected", value:"'ruby1.9.1' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
