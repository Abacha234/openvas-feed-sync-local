# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843401");
  script_cve_id("CVE-2017-3737", "CVE-2017-3738");
  script_tag(name:"creation_date", value:"2017-12-12 06:41:50 +0000 (Tue, 12 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 11:49:00 +0000 (Fri, 19 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-3512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3512-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3512-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-3512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Benjamin discovered that OpenSSL did not correctly prevent
buggy applications that ignore handshake errors from subsequently calling
certain functions. (CVE-2017-3737)

It was discovered that OpenSSL incorrectly performed the x86_64 Montgomery
multiplication procedure. While unlikely, a remote attacker could possibly
use this issue to recover private keys. (CVE-2017-3738)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
