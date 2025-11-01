# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704322");
  script_cve_id("CVE-2018-10933");
  script_tag(name:"creation_date", value:"2018-10-16 22:00:00 +0000 (Tue, 16 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4322)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4322");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4322");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libssh");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh' package(s) announced via the DSA-4322 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Winter-Smith of NCC Group discovered that libssh, a tiny C SSH library, contains an authentication bypass vulnerability in the server code. An attacker can take advantage of this flaw to successfully authenticate without any credentials by presenting the server an SSH2_MSG_USERAUTH_SUCCESS message in place of the SSH2_MSG_USERAUTH_REQUEST message which the server would expect to initiate authentication.

For the stable distribution (stretch), this problem has been fixed in version 0.7.3-2+deb9u1.

We recommend that you upgrade your libssh packages.

For the detailed security status of libssh please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libssh' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);