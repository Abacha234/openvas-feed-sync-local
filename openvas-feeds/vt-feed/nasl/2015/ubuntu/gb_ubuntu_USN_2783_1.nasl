# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842504");
  script_cve_id("CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5196", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7850", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7855", "CVE-2015-7871");
  script_tag(name:"creation_date", value:"2015-10-28 06:18:08 +0000 (Wed, 28 Oct 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 12:15:00 +0000 (Tue, 13 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-2783-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2783-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2783-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-2783-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aleksis Kauppinen discovered that NTP incorrectly handled certain remote
config packets. In a non-default configuration, a remote authenticated
attacker could possibly use this issue to cause NTP to crash, resulting in
a denial of service. (CVE-2015-5146)

Miroslav Lichvar discovered that NTP incorrectly handled logconfig
directives. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a denial
of service. (CVE-2015-5194)

Miroslav Lichvar discovered that NTP incorrectly handled certain statistics
types. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a denial
of service. (CVE-2015-5195)

Miroslav Lichvar discovered that NTP incorrectly handled certain file
paths. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a denial
of service, or overwrite certain files. (CVE-2015-5196, CVE-2015-7703)

Miroslav Lichvar discovered that NTP incorrectly handled certain packets.
A remote attacker could possibly use this issue to cause NTP to hang,
resulting in a denial of service. (CVE-2015-5219)

Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that NTP
incorrectly handled restarting after hitting a panic threshold. A remote
attacker could possibly use this issue to alter the system time on clients.
(CVE-2015-5300)

It was discovered that NTP incorrectly handled autokey data packets. A
remote attacker could possibly use this issue to cause NTP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7691, CVE-2015-7692, CVE-2015-7702)

It was discovered that NTP incorrectly handled memory when processing
certain autokey messages. A remote attacker could possibly use this issue
to cause NTP to consume memory, resulting in a denial of service.
(CVE-2015-7701)

Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that NTP
incorrectly handled rate limiting. A remote attacker could possibly use
this issue to cause clients to stop updating their clock. (CVE-2015-7704,
CVE-2015-7705)

Yves Younan discovered that NTP incorrectly handled logfile and keyfile
directives. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to enter a loop, resulting in a
denial of service. (CVE-2015-7850)

Yves Younan and Aleksander Nikolich discovered that NTP incorrectly handled
ascii conversion. A remote attacker could possibly use this issue to cause
NTP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2015-7852)

Yves Younan discovered that NTP incorrectly handled reference clock memory.
A malicious refclock could possibly use this issue to cause NTP to crash,
resulting in a denial of service, or possibly execute arbitrary ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
