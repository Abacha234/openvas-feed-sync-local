# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704766");
  script_cve_id("CVE-2020-15169", "CVE-2020-8162", "CVE-2020-8164", "CVE-2020-8165", "CVE-2020-8166", "CVE-2020-8167");
  script_tag(name:"creation_date", value:"2020-09-26 03:00:18 +0000 (Sat, 26 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-17 12:15:00 +0000 (Sat, 17 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4766)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4766");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4766");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/rails");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DSA-4766 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the Rails web framework which could result in cross-site scripting, information leaks, code execution, cross-site request forgery or bypass of upload limits.

For the stable distribution (buster), these problems have been fixed in version 2:5.2.2.1+dfsg-1+deb10u2.

We recommend that you upgrade your rails packages.

For the detailed security status of rails please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);