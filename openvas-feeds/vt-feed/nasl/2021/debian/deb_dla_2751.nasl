# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892751");
  script_tag(name:"creation_date", value:"2021-09-01 01:00:10 +0000 (Wed, 01 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-2751)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2751");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2751");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/postgresql-9.6");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.6' package(s) announced via the DLA-2751 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PostgreSQL 9.6.23 fixes this security issue:

Disallow SSL renegotiation more completely (Michael Paquier)

SSL renegotiation has been disabled for some time, but the server would still cooperate with a client-initiated renegotiation request. A maliciously crafted renegotiation request could result in a server crash (see OpenSSL issue CVE-2021-3449). Disable the feature altogether on OpenSSL versions that permit doing so, which are 1.1.0h and newer.

For Debian 9 stretch, this problem has been fixed in version 9.6.23-0+deb9u1.

We recommend that you upgrade your postgresql-9.6 packages.

For the detailed security status of postgresql-9.6 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-9.6' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);