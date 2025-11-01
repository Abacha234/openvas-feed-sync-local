# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840950");
  script_cve_id("CVE-2011-4318");
  script_tag(name:"creation_date", value:"2012-03-16 05:23:16 +0000 (Fri, 16 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1295-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1295-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1295-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the USN-1295-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Dovecot incorrectly validated certificate hostnames
when being used as a POP3 and IMAP proxy. If a remote attacker were able to
perform a machine-in-the-middle attack, this flaw could be exploited to view
sensitive information.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
