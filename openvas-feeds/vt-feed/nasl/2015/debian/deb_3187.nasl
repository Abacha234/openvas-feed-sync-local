# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703187");
  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-7940", "CVE-2014-9654");
  script_tag(name:"creation_date", value:"2015-03-14 23:00:00 +0000 (Sat, 14 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-3187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3187");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3187");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icu' package(s) announced via the DSA-3187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the International Components for Unicode (ICU) library.

CVE-2013-1569

Glyph table issue.

CVE-2013-2383

Glyph table issue.

CVE-2013-2384

Font layout issue.

CVE-2013-2419

Font processing issue.

CVE-2014-6585

Out-of-bounds read.

CVE-2014-6591

Additional out-of-bounds reads.

CVE-2014-7923

Memory corruption in regular expression comparison.

CVE-2014-7926

Memory corruption in regular expression comparison.

CVE-2014-7940

Uninitialized memory.

CVE-2014-9654

More regular expression flaws.

For the stable distribution (wheezy), these problems have been fixed in version 4.8.1.1-12+deb7u2.

For the upcoming stable (jessie) and unstable (sid) distributions, these problems have been fixed in version 52.1-7.1.

We recommend that you upgrade your icu packages.");

  script_tag(name:"affected", value:"'icu' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);