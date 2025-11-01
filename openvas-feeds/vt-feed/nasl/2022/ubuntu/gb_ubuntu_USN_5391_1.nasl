# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845341");
  script_cve_id("CVE-2021-36084", "CVE-2021-36085", "CVE-2021-36086", "CVE-2021-36087");
  script_tag(name:"creation_date", value:"2022-04-28 01:01:53 +0000 (Thu, 28 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-26 22:15:00 +0000 (Mon, 26 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5391-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5391-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5391-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsepol' package(s) announced via the USN-5391-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicolas Iooss discovered that libsepol incorrectly handled memory
when handling policies. An attacker could possibly use this issue
to cause a crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2021-36084)

It was discovered that libsepol incorrectly handled memory when
handling policies. An attacker could possibly use this issue to cause
a crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2021-36085)

It was discovered that libsepol incorrectly handled memory when
handling policies. An attacker could possibly use this issue to cause
a crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affects Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS and Ubuntu 21.10. (CVE-2021-36086)

It was discovered that libsepol incorrectly validated certain data,
leading to a heap overflow. An attacker could possibly use this issue
to cause a crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2021-36087)");

  script_tag(name:"affected", value:"'libsepol' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
