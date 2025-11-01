# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892276");
  script_cve_id("CVE-2020-12108", "CVE-2020-15011");
  script_tag(name:"creation_date", value:"2020-07-17 12:33:14 +0000 (Fri, 17 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-27 16:15:00 +0000 (Tue, 27 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2276)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2276");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2276");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mailman");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mailman' package(s) announced via the DLA-2276 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVEs were reported against src:mailman.

CVE-2020-12108

/options/mailman in GNU Mailman before 2.1.31 allows Arbitrary Content Injection.

CVE-2020-15011

GNU Mailman before 2.1.33 allows arbitrary content injection via the Cgi/private.py private archive login page.

For Debian 9 stretch, these problems have been fixed in version 1:2.1.23-1+deb9u6.

We recommend that you upgrade your mailman packages.

For the detailed security status of mailman please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mailman' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);