# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843029");
  script_cve_id("CVE-2016-2177", "CVE-2016-7055", "CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731", "CVE-2017-3732");
  script_tag(name:"creation_date", value:"2017-02-03 06:40:56 +0000 (Fri, 03 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-3181-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3181-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3181-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-3181-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guido Vranken discovered that OpenSSL used undefined behaviour when
performing pointer arithmetic. A remote attacker could possibly use this
issue to cause OpenSSL to crash, resulting in a denial of service. This
issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS as other
releases were fixed in a previous security update. (CVE-2016-2177)

It was discovered that OpenSSL did not properly handle Montgomery
multiplication, resulting in incorrect results leading to transient
failures. This issue only applied to Ubuntu 16.04 LTS, and Ubuntu 16.10.
(CVE-2016-7055)

It was discovered that OpenSSL did not properly use constant-time
operations when performing ECDSA P-256 signing. A remote attacker could
possibly use this issue to perform a timing attack and recover private
ECDSA keys. This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2016-7056)

Shi Lei discovered that OpenSSL incorrectly handled certain warning alerts.
A remote attacker could possibly use this issue to cause OpenSSL to stop
responding, resulting in a denial of service. (CVE-2016-8610)

Robert Swiecki discovered that OpenSSL incorrectly handled certain
truncated packets. A remote attacker could possibly use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2017-3731)

It was discovered that OpenSSL incorrectly performed the x86_64 Montgomery
squaring procedure. While unlikely, a remote attacker could possibly use
this issue to recover private keys. This issue only applied to Ubuntu 16.04
LTS, and Ubuntu 16.10. (CVE-2017-3732)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
