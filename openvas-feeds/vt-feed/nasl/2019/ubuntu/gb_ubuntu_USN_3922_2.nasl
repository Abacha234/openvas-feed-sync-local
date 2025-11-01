# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843985");
  script_cve_id("CVE-2019-9022", "CVE-2019-9637", "CVE-2019-9638", "CVE-2019-9639", "CVE-2019-9640", "CVE-2019-9641", "CVE-2019-9675");
  script_tag(name:"creation_date", value:"2019-04-24 02:00:58 +0000 (Wed, 24 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:49:00 +0000 (Tue, 05 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3922-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3922-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3922-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-3922-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3922-1 fixed vulnerabilities in PHP. This update provides the corresponding
update for Ubuntu 14.04 LTS.

It was discovered that PHP incorrectly handled certain files. An attacker
could possibly use this issue to access sensitive information.
(CVE-2019-9022)

It was discovered that PHP incorrectly handled certain files. An attacker
could possibly use this issue to execute arbitrary code.
(CVE-2019-9675)

Original advisory details:

 It was discovered that PHP incorrectly handled certain inputs. An attacker
 could possibly use this issue to expose sensitive information. (CVE-2019-9637,
 CVE-2019-9638, CVE-2019-9639, CVE-2019-9640, CVE-2019-9641)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
