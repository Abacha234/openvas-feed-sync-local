# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704452");
  script_cve_id("CVE-2018-11307", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-14720", "CVE-2018-14721", "CVE-2018-19360", "CVE-2018-19361", "CVE-2018-19362", "CVE-2019-12086");
  script_tag(name:"creation_date", value:"2019-05-26 02:00:15 +0000 (Sun, 26 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 14:15:00 +0000 (Mon, 31 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4452)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4452");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4452");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jackson-databind");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jackson-databind' package(s) announced via the DSA-4452 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in jackson-databind, a Java library to parse JSON and other data formats which could result in information disclosure or the execution of arbitrary code.

For the stable distribution (stretch), these problems have been fixed in version 2.8.6-1+deb9u5.

We recommend that you upgrade your jackson-databind packages.

For the detailed security status of jackson-databind please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);