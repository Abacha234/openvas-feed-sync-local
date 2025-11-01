# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703828");
  script_tag(name:"creation_date", value:"2017-04-09 22:00:00 +0000 (Sun, 09 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3828)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3828");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3828");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-3828 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Dovecot email server is vulnerable to a denial of service attack. When the dict passdb and userdb are used for user authentication, the username sent by the IMAP/POP3 client is sent through var_expand() to perform %variable expansion. Sending specially crafted %variable fields could result in excessive memory usage causing the process to crash (and restart).

For the stable distribution (jessie), this problem has been fixed in version 1:2.2.13-12~deb8u2.

We recommend that you upgrade your dovecot packages.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);