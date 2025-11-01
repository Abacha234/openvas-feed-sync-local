# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844501");
  script_cve_id("CVE-2019-17514", "CVE-2019-20907", "CVE-2019-9674", "CVE-2020-14422");
  script_tag(name:"creation_date", value:"2020-07-23 03:00:53 +0000 (Thu, 23 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 18:15:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4428-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4428-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4428-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.4, python3.5, python3.6, python3.8' package(s) announced via the USN-4428-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python documentation had a misleading information.
A security issue could be possibly caused by wrong assumptions of this information.
This issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM, Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-17514)

It was discovered that Python incorrectly handled certain TAR archives.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2019-20907)

It was discovered that incorrectly handled certain ZIP files. An attacker
could possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM, Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-9674)

It was discovered that Python incorrectly handled certain IP values.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-14422)");

  script_tag(name:"affected", value:"'python2.7, python3.4, python3.5, python3.6, python3.8' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
