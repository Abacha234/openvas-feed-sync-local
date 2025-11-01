# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840550");
  script_cve_id("CVE-2008-7270", "CVE-2010-4180");
  script_tag(name:"creation_date", value:"2010-12-23 06:38:58 +0000 (Thu, 23 Dec 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1029-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1029-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1029-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-1029-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an old bug workaround in the SSL/TLS
server code allowed an attacker to modify the stored session cache
ciphersuite. This could possibly allow an attacker to downgrade the
ciphersuite to a weaker one on subsequent connections. (CVE-2010-4180)

It was discovered that an old bug workaround in the SSL/TLS
server code allowed an attacker to modify the stored session cache
ciphersuite. An attacker could possibly take advantage of this to
force the use of a disabled cipher. This vulnerability only affects
the versions of OpenSSL in Ubuntu 6.06 LTS, Ubuntu 8.04 LTS, and
Ubuntu 9.10. (CVE-2008-7270)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
