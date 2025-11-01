# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704418");
  script_cve_id("CVE-2019-7524");
  script_tag(name:"creation_date", value:"2019-03-27 22:00:00 +0000 (Wed, 27 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-4418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4418");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4418");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-4418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the Dovecot email server. When reading FTS or POP3-UIDL headers from the Dovecot index, the input buffer size is not bounds-checked. An attacker with the ability to modify dovecot indexes, can take advantage of this flaw for privilege escalation or the execution of arbitrary code with the permissions of the dovecot user. Only installations using the FTS or pop3 migration plugins are affected.

For the stable distribution (stretch), this problem has been fixed in version 1:2.2.27-3+deb9u4.

We recommend that you upgrade your dovecot packages.

For the detailed security status of dovecot please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);