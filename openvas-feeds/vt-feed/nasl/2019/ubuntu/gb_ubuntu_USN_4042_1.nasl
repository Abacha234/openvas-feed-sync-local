# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844074");
  script_cve_id("CVE-2017-9865", "CVE-2018-18897", "CVE-2018-20662", "CVE-2019-10018", "CVE-2019-10019", "CVE-2019-10021", "CVE-2019-10023", "CVE-2019-10872", "CVE-2019-10873", "CVE-2019-12293", "CVE-2019-9200", "CVE-2019-9631", "CVE-2019-9903");
  script_tag(name:"creation_date", value:"2019-06-28 02:00:30 +0000 (Fri, 28 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-23 12:15:00 +0000 (Thu, 23 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4042-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4042-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4042-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-4042-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that poppler incorrectly handled certain files. If a user
or automated system were tricked into opening a crafted PDF file, an
attacker could cause a denial of service, or possibly execute arbitrary
code");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
