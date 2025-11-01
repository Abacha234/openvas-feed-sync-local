# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843958");
  script_cve_id("CVE-2018-1000100", "CVE-2018-13005", "CVE-2018-13006", "CVE-2018-20760", "CVE-2018-20761", "CVE-2018-20762", "CVE-2018-20763", "CVE-2018-7752");
  script_tag(name:"creation_date", value:"2019-04-03 06:40:31 +0000 (Wed, 03 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 18:58:00 +0000 (Fri, 29 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3926-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3926-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3926-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpac' package(s) announced via the USN-3926-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GPAC MP4Box utility incorrectly handled certain
memory operations. If an user or automated system were tricked into opening a
specially crafted MP4 file, a remote attacker could use this issue to cause
MP4Box to crash, resulting in a denial of service, or possibly execute
arbitrary code.");

  script_tag(name:"affected", value:"'gpac' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
