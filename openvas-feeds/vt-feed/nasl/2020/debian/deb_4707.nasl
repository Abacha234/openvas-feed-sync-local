# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704707");
  script_cve_id("CVE-2020-14093", "CVE-2020-14954");
  script_tag(name:"creation_date", value:"2020-06-21 03:00:06 +0000 (Sun, 21 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4707)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4707");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4707");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mutt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mutt' package(s) announced via the DSA-4707 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Damian Poddebniak and Fabian Ising discovered two security issues in the STARTTLS handling of the Mutt mail client, which could enable MITM attacks.

For the oldstable distribution (stretch), these problems have been fixed in version 1.7.2-1+deb9u3.

For the stable distribution (buster), these problems have been fixed in version 1.10.1-2.1+deb10u2.

We recommend that you upgrade your mutt packages.

For the detailed security status of mutt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mutt' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);