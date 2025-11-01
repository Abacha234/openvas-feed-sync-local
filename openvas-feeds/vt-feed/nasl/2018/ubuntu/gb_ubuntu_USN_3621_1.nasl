# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843695");
  script_cve_id("CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079");
  script_tag(name:"creation_date", value:"2018-10-26 04:07:58 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 13:29:00 +0000 (Mon, 20 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3621-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3621-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3621-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1, ruby2.0, ruby2.3' package(s) announced via the USN-3621-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ruby incorrectly handled certain inputs. An attacker
could possibly use this to access sensitive information. (CVE-2018-1000073)

It was discovered that Ruby incorrectly handled certain files. An attacker
could possibly use this to execute arbitrary code. (CVE-2018-1000074)

It was discovered that Ruby incorrectly handled certain files. An attacker
could possibly use this to cause a denial of service. (CVE-2018-1000075)

It was discovered that Ruby incorrectly handled certain crypto signatures.
An attacker could possibly use this to execute arbitrary code. (CVE-2018-1000076)

It was discovered that Ruby incorrectly handled certain inputs. An attacker
could possibly use this to execute arbitrary code. (CVE-2018-1000077,
CVE-2018-1000078, CVE-2018-1000079)");

  script_tag(name:"affected", value:"'ruby1.9.1, ruby2.0, ruby2.3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
