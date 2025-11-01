# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704160");
  script_cve_id("CVE-2018-8754");
  script_tag(name:"creation_date", value:"2018-03-31 22:00:00 +0000 (Sat, 31 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-14 18:14:00 +0000 (Wed, 14 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4160");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4160");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libevt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libevt' package(s) announced via the DSA-4160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that insufficient input sanitising in libevt, a library to access the Windows Event Log (EVT) format, could result in denial of service if a malformed EVT file is processed.

For the stable distribution (stretch), this problem has been fixed in version 20170120-1+deb9u1.

We recommend that you upgrade your libevt packages.

For the detailed security status of libevt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libevt' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);