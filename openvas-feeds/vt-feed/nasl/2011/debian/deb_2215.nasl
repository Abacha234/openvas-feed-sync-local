# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69559");
  script_cve_id("CVE-2011-1572");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2215");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2215");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gitolite' package(s) announced via the DSA-2215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dylan Simon discovered that gitolite, a SSH-based gatekeeper for Git repositories, is prone to directory traversal attacks when restricting admin defined commands (ADC). This allows an attacker to execute arbitrary commands with privileges of the gitolite server via crafted command names.

Please note that this only affects installations that have ADC enabled (not the Debian default).

The oldstable distribution (lenny) is not affected by this problem, it does not include gitolite.

For the stable distribution (squeeze), this problem has been fixed in version 1.5.4-2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 1.5.7-2.

For the unstable distribution (sid), this problem has been fixed in version 1.5.7-2.

We recommend that you upgrade your gitolite packages.");

  script_tag(name:"affected", value:"'gitolite' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);