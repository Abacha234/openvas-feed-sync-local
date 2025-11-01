# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845277");
  script_cve_id("CVE-2019-20044", "CVE-2021-45444");
  script_tag(name:"creation_date", value:"2022-03-15 02:00:23 +0000 (Tue, 15 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 20:16:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5325-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5325-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh' package(s) announced via the USN-5325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sam Foxman discovered that Zsh incorrectly handled certain inputs.
An attacker could possibly use this issue to regain dropped privileges.
(CVE-2019-20044)

It was discovered that Zsh incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2021-45444)");

  script_tag(name:"affected", value:"'zsh' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
