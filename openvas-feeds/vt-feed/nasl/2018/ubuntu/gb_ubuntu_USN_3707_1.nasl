# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843586");
  script_cve_id("CVE-2018-7182", "CVE-2018-7183", "CVE-2018-7184", "CVE-2018-7185");
  script_tag(name:"creation_date", value:"2018-07-10 03:56:31 +0000 (Tue, 10 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-3707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3707-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3707-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-3707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yihan Lian discovered that NTP incorrectly handled certain malformed mode 6
packets. A remote attacker could possibly use this issue to cause ntpd to
crash, resulting in a denial of service. This issue only affected Ubuntu
17.10 and Ubuntu 18.04 LTS. (CVE-2018-7182)

Michael Macnair discovered that NTP incorrectly handled certain responses.
A remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-7183)

Miroslav Lichvar discovered that NTP incorrectly handled certain
zero-origin timestamps. A remote attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 17.10 and Ubuntu
18.04 LTS. (CVE-2018-7184)

Miroslav Lichvar discovered that NTP incorrectly handled certain
zero-origin timestamps. A remote attacker could possibly use this issue to
cause a denial of service. (CVE-2018-7185)");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
