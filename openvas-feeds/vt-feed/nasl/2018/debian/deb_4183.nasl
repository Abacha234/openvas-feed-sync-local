# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704183");
  script_cve_id("CVE-2018-0490");
  script_tag(name:"creation_date", value:"2018-04-27 22:00:00 +0000 (Fri, 27 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-30 14:58:00 +0000 (Tue, 30 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-4183)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4183");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4183");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tor");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tor' package(s) announced via the DSA-4183 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that Tor, a connection-based low-latency anonymous communication system, contains a protocol-list handling bug that could be used to remotely crash directory authorities with a null-pointer exception (TROVE-2018-001).

For the stable distribution (stretch), this problem has been fixed in version 0.2.9.15-1.

We recommend that you upgrade your tor packages.

For the detailed security status of tor please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tor' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);