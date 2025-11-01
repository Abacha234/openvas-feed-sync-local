# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844030");
  script_cve_id("CVE-2018-10844", "CVE-2018-10845", "CVE-2018-10846", "CVE-2019-3829", "CVE-2019-3836");
  script_tag(name:"creation_date", value:"2019-05-31 02:00:34 +0000 (Fri, 31 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-30 16:29:00 +0000 (Thu, 30 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3999-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3999-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3999-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28' package(s) announced via the USN-3999-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eyal Ronen, Kenneth G. Paterson, and Adi Shamir discovered that GnuTLS was
vulnerable to a timing side-channel attack known as the 'Lucky Thirteen'
issue. A remote attacker could possibly use this issue to perform
plaintext-recovery attacks via analysis of timing data. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-10844,
CVE-2018-10845, CVE-2018-10846)

Tavis Ormandy discovered that GnuTLS incorrectly handled memory when
verifying certain X.509 certificates. A remote attacker could use this
issue to cause GnuTLS to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu 18.04 LTS,
Ubuntu 18.10, and Ubuntu 19.04. (CVE-2019-3829)

It was discovered that GnuTLS incorrectly handled certain post-handshake
messages. A remote attacker could use this issue to cause GnuTLS to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.10 and Ubuntu 19.04. (CVE-2019-3836)");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
