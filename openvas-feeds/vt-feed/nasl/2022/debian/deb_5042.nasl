# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705042");
  script_cve_id("CVE-2021-45085", "CVE-2021-45086", "CVE-2021-45087", "CVE-2021-45088");
  script_tag(name:"creation_date", value:"2022-01-14 02:00:09 +0000 (Fri, 14 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-17 20:22:00 +0000 (Fri, 17 Dec 2021)");

  script_name("Debian: Security Advisory (DSA-5042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5042");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5042");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/epiphany-browser");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'epiphany-browser' package(s) announced via the DSA-5042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Epiphany, the GNOME web browser, allowing XSS attacks under certain circumstances.

For the stable distribution (bullseye), these problems have been fixed in version 3.38.2-1+deb11u1.

We recommend that you upgrade your epiphany-browser packages.

For the detailed security status of epiphany-browser please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'epiphany-browser' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);