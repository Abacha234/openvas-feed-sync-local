# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704130");
  script_cve_id("CVE-2017-14461", "CVE-2017-15130", "CVE-2017-15132");
  script_tag(name:"creation_date", value:"2018-03-01 23:00:00 +0000 (Thu, 01 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4130");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4130");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-4130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Dovecot email server. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-14461

Aleksandar Nikolic of Cisco Talos and flxflndy discovered that Dovecot does not properly parse invalid email addresses, which may cause a crash or leak memory contents to an attacker.

CVE-2017-15130

It was discovered that TLS SNI config lookups may lead to excessive memory usage, causing imap-login/pop3-login VSZ limit to be reached and the process restarted, resulting in a denial of service. Only Dovecot configurations containing local_name { } or local { } configuration blocks are affected.

CVE-2017-15132

It was discovered that Dovecot contains a memory leak flaw in the login process on aborted SASL authentication.

For the oldstable distribution (jessie), these problems have been fixed in version 1:2.2.13-12~deb8u4.

For the stable distribution (stretch), these problems have been fixed in version 1:2.2.27-3+deb9u2.

We recommend that you upgrade your dovecot packages.

For the detailed security status of dovecot please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);