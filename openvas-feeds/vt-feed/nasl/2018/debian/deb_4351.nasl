# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704351");
  script_cve_id("CVE-2018-19296");
  script_tag(name:"creation_date", value:"2018-12-06 23:00:00 +0000 (Thu, 06 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 18:34:00 +0000 (Fri, 21 May 2021)");

  script_name("Debian: Security Advisory (DSA-4351)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4351");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4351");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libphp-phpmailer");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libphp-phpmailer' package(s) announced via the DSA-4351 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHPMailer, a library to send email from PHP applications, is prone to a PHP object injection vulnerability, potentially allowing a remote attacker to execute arbitrary code.

For the stable distribution (stretch), this problem has been fixed in version 5.2.14+dfsg-2.3+deb9u1.

We recommend that you upgrade your libphp-phpmailer packages.

For the detailed security status of libphp-phpmailer please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libphp-phpmailer' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);