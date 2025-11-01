# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841925");
  script_cve_id("CVE-2012-1016", "CVE-2013-1415", "CVE-2013-1416", "CVE-2013-1418", "CVE-2013-6800", "CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345");
  script_tag(name:"creation_date", value:"2014-08-12 03:56:03 +0000 (Tue, 12 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2310-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2310-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2310-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-2310-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Kerberos incorrectly handled certain crafted Draft 9
requests. A remote attacker could use this issue to cause the daemon to
crash, resulting in a denial of service. This issue only affected Ubuntu
12.04 LTS. (CVE-2012-1016)

It was discovered that Kerberos incorrectly handled certain malformed
KRB5_PADATA_PK_AS_REQ AS-REQ requests. A remote attacker could use this
issue to cause the daemon to crash, resulting in a denial of service. This
issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS. (CVE-2013-1415)

It was discovered that Kerberos incorrectly handled certain crafted TGS-REQ
requests. A remote authenticated attacker could use this issue to cause the
daemon to crash, resulting in a denial of service. This issue only affected
Ubuntu 10.04 LTS and Ubuntu 12.04 LTS. (CVE-2013-1416)

It was discovered that Kerberos incorrectly handled certain crafted
requests when multiple realms were configured. A remote attacker could use
this issue to cause the daemon to crash, resulting in a denial of service.
This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
(CVE-2013-1418, CVE-2013-6800)

It was discovered that Kerberos incorrectly handled certain invalid tokens.
If a remote attacker were able to perform a machine-in-the-middle attack, this
flaw could be used to cause the daemon to crash, resulting in a denial of
service. (CVE-2014-4341, CVE-2014-4342)

It was discovered that Kerberos incorrectly handled certain mechanisms when
used with SPNEGO. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could be used to cause clients to
crash, resulting in a denial of service. (CVE-2014-4343)

It was discovered that Kerberos incorrectly handled certain continuation
tokens during SPNEGO negotiations. A remote attacker could use this issue
to cause the daemon to crash, resulting in a denial of service.
(CVE-2014-4344)

Tomas Kuthan and Greg Hudson discovered that the Kerberos kadmind daemon
incorrectly handled buffers when used with the LDAP backend. A remote
attacker could use this issue to cause the daemon to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2014-4345)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
