# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843091");
  script_cve_id("CVE-2014-9601", "CVE-2016-9189", "CVE-2016-9190");
  script_tag(name:"creation_date", value:"2017-03-14 04:47:53 +0000 (Tue, 14 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Ubuntu: Security Advisory (USN-3229-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3229-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3229-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-imaging' package(s) announced via the USN-3229-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Python Imaging Library incorrectly handled
certain compressed text chunks in PNG images. A remote attacker could
possibly use this issue to cause the Python Imaging Library to crash,
resulting in a denial of service. (CVE-2014-9601)

Cris Neckar discovered that the Python Imaging Library incorrectly handled
certain malformed images. A remote attacker could use this issue to cause
the Python Imaging Library to crash, resulting in a denial of service, or
possibly obtain sensitive information. (CVE-2016-9189)

Cris Neckar discovered that the Python Imaging Library incorrectly handled
certain malformed images. A remote attacker could use this issue to cause
the Python Imaging Library to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-9190)");

  script_tag(name:"affected", value:"'python-imaging' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
