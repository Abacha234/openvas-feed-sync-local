# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844173");
  script_cve_id("CVE-2019-13962", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498", "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776", "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");
  script_tag(name:"creation_date", value:"2019-09-12 02:01:23 +0000 (Thu, 12 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:00:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-4131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4131-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4131-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the USN-4131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that VLC incorrectly handled certain media files. If a
user were tricked into opening a specially-crafted file, a remote attacker
could use this issue to cause VLC to crash, resulting in a denial of
service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'vlc' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
