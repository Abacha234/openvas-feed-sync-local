# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842936");
  script_cve_id("CVE-2016-6893", "CVE-2016-7123");
  script_tag(name:"creation_date", value:"2016-11-08 10:22:52 +0000 (Tue, 08 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");

  script_name("Ubuntu: Security Advisory (USN-3118-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3118-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3118-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman' package(s) announced via the USN-3118-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Mailman administrative web interface did not
protect against cross-site request forgery (CSRF) attacks. If an
authenticated user were tricked into visiting a malicious website while
logged into Mailman, a remote attacker could perform administrative
actions. This issue only affected Ubuntu 12.04 LTS. (CVE-2016-7123)

Nishant Agarwala discovered that the Mailman user options page did not
protect against cross-site request forgery (CSRF) attacks. If an
authenticated user were tricked into visiting a malicious website while
logged into Mailman, a remote attacker could modify user options.
(CVE-2016-6893)");

  script_tag(name:"affected", value:"'mailman' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
