# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840547");
  script_cve_id("CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021");
  script_tag(name:"creation_date", value:"2010-12-23 06:38:58 +0000 (Thu, 23 Dec 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 15:46:00 +0000 (Tue, 21 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-1030-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1030-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1030-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-1030-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Kerberos did not properly determine the
acceptability of certain checksums. A remote attacker could use certain
checksums to alter the prompt message, modify a response to a Key
Distribution Center (KDC) or forge a KRB-SAFE message. (CVE-2010-1323)

It was discovered that Kerberos did not properly determine the
acceptability of certain checksums. A remote attacker could use certain
checksums to forge GSS tokens or gain privileges. This issue only affected
Ubuntu 9.10, 10.04 LTS and 10.10. (CVE-2010-1324)

It was discovered that Kerberos did not reject RC4 key-derivation
checksums. An authenticated remote user could use this issue to forge
AD-SIGNEDPATH or AD-KDC-ISSUED signatures and possibly gain privileges.
This issue only affected Ubuntu 10.04 LTS and 10.10. (CVE-2010-4020)

It was discovered that Kerberos did not properly restrict the use of TGT
credentials for armoring TGS requests. A remote authenticated user could
use this flaw to impersonate a client. This issue only affected Ubuntu
9.10. (CVE-2010-4021)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
