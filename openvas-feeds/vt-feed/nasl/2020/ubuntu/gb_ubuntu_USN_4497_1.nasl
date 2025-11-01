# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844577");
  script_cve_id("CVE-2016-9112", "CVE-2018-20847", "CVE-2018-21010", "CVE-2019-12973", "CVE-2020-15389", "CVE-2020-6851", "CVE-2020-8112");
  script_tag(name:"creation_date", value:"2020-09-16 03:00:30 +0000 (Wed, 16 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-02 12:15:00 +0000 (Fri, 02 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4497-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4497-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2' package(s) announced via the USN-4497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJPEG incorrectly handled certain image files. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2016-9112)

It was discovered that OpenJPEG did not properly handle certain input. If
OpenJPEG were supplied with specially crafted input, it could be made to crash
or potentially execute arbitrary code.
(CVE-2018-20847, CVE-2018-21010, CVE-2020-6851, CVE-2020-8112, CVE-2020-15389)

It was discovered that OpenJPEG incorrectly handled certain BMP files. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2019-12973)");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
