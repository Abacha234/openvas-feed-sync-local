# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845279");
  script_cve_id("CVE-2022-26495", "CVE-2022-26496");
  script_tag(name:"creation_date", value:"2022-03-15 02:00:25 +0000 (Tue, 15 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-11 14:37:00 +0000 (Fri, 11 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5323-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5323-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5323-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbd' package(s) announced via the USN-5323-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that NBD incorrectly handled name length fields. A remote
attacker could use this issue to cause NBD to crash, resulting in a denial
of service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'nbd' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
