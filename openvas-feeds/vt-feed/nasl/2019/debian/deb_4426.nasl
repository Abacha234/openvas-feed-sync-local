# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704426");
  script_cve_id("CVE-2019-10868");
  script_tag(name:"creation_date", value:"2019-04-08 02:00:09 +0000 (Mon, 08 Apr 2019)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-26 12:45:00 +0000 (Wed, 26 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4426");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4426");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tryton-server");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tryton-server' package(s) announced via the DSA-4426 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cedric Krier discovered that missing access validation in Tryton could result in information disclosure.

For the stable distribution (stretch), this problem has been fixed in version 4.2.1-2+deb9u1.

We recommend that you upgrade your tryton-server packages.

For the detailed security status of tryton-server please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tryton-server' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);