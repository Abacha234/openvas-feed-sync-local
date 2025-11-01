# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840985");
  script_cve_id("CVE-2006-7250", "CVE-2012-1165", "CVE-2012-2110");
  script_tag(name:"creation_date", value:"2012-04-20 04:51:13 +0000 (Fri, 20 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1424-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1424-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-1424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL could be made to dereference a NULL pointer
when processing S/MIME messages. A remote attacker could use this to cause
a denial of service. These issues did not affect Ubuntu 8.04 LTS.
(CVE-2006-7250, CVE-2012-1165)

Tavis Ormandy discovered that OpenSSL did not properly perform bounds
checking when processing DER data via BIO or FILE functions. A remote
attacker could trigger this flaw in services that used SSL to cause a
denial of service or possibly execute arbitrary code with application
privileges. (CVE-2012-2110)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
