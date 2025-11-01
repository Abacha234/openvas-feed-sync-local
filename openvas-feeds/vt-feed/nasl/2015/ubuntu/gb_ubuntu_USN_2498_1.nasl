# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842089");
  script_cve_id("CVE-2014-5351", "CVE-2014-5352", "CVE-2014-5353", "CVE-2014-5354", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_tag(name:"creation_date", value:"2015-02-11 04:39:46 +0000 (Wed, 11 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2498-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2498-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2498-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-2498-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Kerberos incorrectly sent old keys in response to a
-randkey -keepold request. An authenticated remote attacker could use this
issue to forge tickets by leveraging administrative access. This issue
only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-5351)

It was discovered that the libgssapi_krb5 library incorrectly processed
security context handles. A remote attacker could use this issue to cause
a denial of service, or possibly execute arbitrary code. (CVE-2014-5352)

Patrik Kis discovered that Kerberos incorrectly handled LDAP queries with
no results. An authenticated remote attacker could use this issue to cause
the KDC to crash, resulting in a denial of service. (CVE-2014-5353)

It was discovered that Kerberos incorrectly handled creating database
entries for a keyless principal when using LDAP. An authenticated remote
attacker could use this issue to cause the KDC to crash, resulting in a
denial of service. (CVE-2014-5354)

It was discovered that Kerberos incorrectly handled memory when processing
XDR data. A remote attacker could use this issue to cause kadmind to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2014-9421)

It was discovered that Kerberos incorrectly handled two-component server
principals. A remote attacker could use this issue to perform impersonation
attacks. (CVE-2014-9422)

It was discovered that the libgssrpc library leaked uninitialized bytes. A
remote attacker could use this issue to possibly obtain sensitive
information. (CVE-2014-9423)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
