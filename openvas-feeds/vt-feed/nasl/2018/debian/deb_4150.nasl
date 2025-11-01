# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704150");
  script_cve_id("CVE-2017-15422");
  script_tag(name:"creation_date", value:"2018-03-22 23:00:00 +0000 (Thu, 22 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 17:54:00 +0000 (Wed, 07 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4150");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4150");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/icu");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icu' package(s) announced via the DSA-4150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an integer overflow in the International Components for Unicode (ICU) library could result in denial of service and potentially the execution of arbitrary code.

For the oldstable distribution (jessie), this problem has been fixed in version 52.1-8+deb8u7.

For the stable distribution (stretch), this problem has been fixed in version 57.1-6+deb9u2.

We recommend that you upgrade your icu packages.

For the detailed security status of icu please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'icu' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);