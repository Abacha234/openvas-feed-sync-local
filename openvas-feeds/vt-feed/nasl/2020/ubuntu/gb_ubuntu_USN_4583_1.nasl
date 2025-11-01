# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844654");
  script_cve_id("CVE-2020-7069", "CVE-2020-7070");
  script_tag(name:"creation_date", value:"2020-10-15 03:00:30 +0000 (Thu, 15 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4583-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4583-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4583-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0, php7.2, php7.4' package(s) announced via the USN-4583-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain encrypt ciphers.
An attacker could possibly use this issue to decrease security or cause
incorrect encryption data. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-7069)

It was discorevered that PHP incorrectly handled certain HTTP cookies.
An attacker could possibly use this issue to forge cookie which is supposed to
be secure. (CVE-2020-7070)");

  script_tag(name:"affected", value:"'php5, php7.0, php7.2, php7.4' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
