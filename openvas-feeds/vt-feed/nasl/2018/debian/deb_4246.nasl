# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704246");
  script_cve_id("CVE-2018-0618");
  script_tag(name:"creation_date", value:"2018-07-14 22:00:00 +0000 (Sat, 14 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-06 20:15:00 +0000 (Wed, 06 May 2020)");

  script_name("Debian: Security Advisory (DSA-4246)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4246");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4246");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mailman");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mailman' package(s) announced via the DSA-4246 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Toshitsugu Yoneyama of Mitsui Bussan Secure Directions, Inc. discovered that mailman, a web-based mailing list manager, is prone to a cross-site scripting flaw allowing a malicious listowner to inject scripts into the listinfo page, due to not validated input in the host_name field.

For the stable distribution (stretch), this problem has been fixed in version 1:2.1.23-1+deb9u3.

We recommend that you upgrade your mailman packages.

For the detailed security status of mailman please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mailman' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);