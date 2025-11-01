# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843098");
  script_cve_id("CVE-2016-7444", "CVE-2016-8610", "CVE-2017-5334", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337");
  script_tag(name:"creation_date", value:"2017-03-21 04:50:50 +0000 (Tue, 21 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3183-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3183-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3183-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls26' package(s) announced via the USN-3183-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3183-1 fixed CVE-2016-8610 in GnuTLS in Ubuntu 16.04 LTS and Ubuntu
16.10. This update provides the corresponding update for Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS.

Original advisory details:

 Stefan Buehler discovered that GnuTLS incorrectly verified the serial
 length of OCSP responses. A remote attacker could possibly use this issue
 to bypass certain certificate validation measures. This issue only applied
 to Ubuntu 16.04 LTS. (CVE-2016-7444)

 Shi Lei discovered that GnuTLS incorrectly handled certain warning alerts.
 A remote attacker could possibly use this issue to cause GnuTLS to hang,
 resulting in a denial of service. This issue has only been addressed in
 Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-8610)

 It was discovered that GnuTLS incorrectly decoded X.509 certificates with a
 Proxy Certificate Information extension. A remote attacker could use this
 issue to cause GnuTLS to crash, resulting in a denial of service, or
 possibly execute arbitrary code. This issue only affected Ubuntu 16.04 LTS
 and Ubuntu 16.10. (CVE-2017-5334)

 It was discovered that GnuTLS incorrectly handled certain OpenPGP
 certificates. A remote attacker could possibly use this issue to cause
 GnuTLS to crash, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2017-5335, CVE-2017-5336, CVE-2017-5337)");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
