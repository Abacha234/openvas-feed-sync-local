# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843205");
  script_cve_id("CVE-2017-7507", "CVE-2017-7869");
  script_tag(name:"creation_date", value:"2017-06-14 04:40:43 +0000 (Wed, 14 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3318-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3318-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls26, gnutls28' package(s) announced via the USN-3318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hubert Kario discovered that GnuTLS incorrectly handled decoding a status
response TLS extension. A remote attacker could possibly use this issue to
cause GnuTLS to crash, resulting in a denial of service. This issue only
applied to Ubuntu 16.04 LTS, Ubuntu 16.10 and Ubuntu 17.04. (CVE-2017-7507)

It was discovered that GnuTLS incorrectly handled decoding certain OpenPGP
certificates. A remote attacker could use this issue to cause GnuTLS to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2017-7869)");

  script_tag(name:"affected", value:"'gnutls26, gnutls28' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
