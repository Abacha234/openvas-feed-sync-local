# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842769");
  script_cve_id("CVE-2016-1938", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2805", "CVE-2016-2807");
  script_tag(name:"creation_date", value:"2016-05-19 03:21:10 +0000 (Thu, 19 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-2973-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2973-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2973-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2973-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, Tyson Smith, and Phil Ringalda discovered multiple
memory safety issues in Thunderbird. If a user were tricked in to opening
a specially crafted message, an attacker could potentially exploit these
to cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-2805, CVE-2016-2807)

Hanno Bock discovered that calculations with mp_div and mp_exptmod in NSS
produce incorrect results in some circumstances, resulting in
cryptographic weaknesses. (CVE-2016-1938)

A use-after-free was discovered in ssl3_HandleECDHServerKeyExchange in
NSS. A remote attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-1978)

A use-after-free was discovered in PK11_ImportDERPrivateKeyInfoAndReturnKey
in NSS. A remote attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-1979)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
