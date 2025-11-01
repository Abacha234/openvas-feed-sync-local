# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892517");
  script_cve_id("CVE-2020-24386", "CVE-2020-25275");
  script_tag(name:"creation_date", value:"2021-01-11 13:00:50 +0000 (Mon, 11 Jan 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 03:15:00 +0000 (Wed, 20 Jan 2021)");

  script_name("Debian: Security Advisory (DLA-2517)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2517");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2517");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DLA-2517 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were two issues in the Dovecot IMAP server:

CVE-2020-24386

An issue was discovered in Dovecot before 2.3.13. By using IMAP IDLE, an authenticated attacker can trigger unhibernation via attacker-controlled parameters, leading to access to other users' email messages (and path disclosure).

CVE-2020-25275

Dovecot before 2.3.13 has Improper Input Validation in lda, lmtp, and imap, leading to an application crash via a crafted email message with certain choices for ten thousand MIME parts.

For Debian 9 Stretch, these problems have been fixed in version 1:2.2.27-3+deb9u7.

We recommend that you upgrade your dovecot packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);