# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845477");
  script_cve_id("CVE-2021-45085", "CVE-2021-45086", "CVE-2021-45087", "CVE-2022-29536");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-02 19:40:00 +0000 (Mon, 02 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5561-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5561-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5561-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'epiphany-browser' package(s) announced via the USN-5561-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNOME Web incorrectly filtered certain strings. A
remote attacker could use this issue to perform cross-site scripting (XSS)
attacks. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-45085,
CVE-2021-45086, CVE-2021-45087)

It was discovered that GNOME Web incorrectly handled certain long page
titles. A remote attacker could use this issue to cause GNOME Web to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2022-29536)");

  script_tag(name:"affected", value:"'epiphany-browser' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
