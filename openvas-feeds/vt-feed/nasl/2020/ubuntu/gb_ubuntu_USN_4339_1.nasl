# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844403");
  script_cve_id("CVE-2017-9111", "CVE-2017-9113", "CVE-2017-9115", "CVE-2018-18444", "CVE-2020-11758", "CVE-2020-11759", "CVE-2020-11760", "CVE-2020-11761", "CVE-2020-11762", "CVE-2020-11763", "CVE-2020-11764", "CVE-2020-11765");
  script_tag(name:"creation_date", value:"2020-04-28 03:00:15 +0000 (Tue, 28 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-23 20:15:00 +0000 (Mon, 23 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-4339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4339-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4339-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the USN-4339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brandon Perry discovered that OpenEXR incorrectly handled certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, a remote attacker could cause a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 20.04 LTS.
(CVE-2017-9111, CVE-2017-9113, CVE-2017-9115)

Tan Jie discovered that OpenEXR incorrectly handled certain malformed EXR
image files. If a user were tricked into opening a crafted EXR image file,
a remote attacker could cause a denial of service, or possibly execute
arbitrary code. This issue only applied to Ubuntu 20.04 LTS.
(CVE-2018-18444)

Samuel Gross discovered that OpenEXR incorrectly handled certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, a remote attacker could cause a denial of service, or possibly
execute arbitrary code. (CVE-2020-11758, CVE-2020-11759, CVE-2020-11760,
CVE-2020-11761, CVE-2020-11762, CVE-2020-11763, CVE-2020-11764)

It was discovered that OpenEXR incorrectly handled certain malformed EXR
image files. If a user were tricked into opening a crafted EXR image
file, a remote attacker could cause a denial of service. (CVE-2020-11765)");

  script_tag(name:"affected", value:"'openexr' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
