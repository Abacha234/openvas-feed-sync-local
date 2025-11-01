# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703302");
  script_cve_id("CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_tag(name:"creation_date", value:"2015-07-05 22:00:00 +0000 (Sun, 05 Jul 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3302");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3302");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libwmf' package(s) announced via the DSA-3302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient input sanitising in libwmf, a library to process Windows metafile data, may result in denial of service or the execution of arbitrary code if a malformed WMF file is opened.

For the oldstable distribution (wheezy), these problems have been fixed in version 0.2.8.4-10.3+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 0.2.8.4-10.3+deb8u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your libwmf packages.");

  script_tag(name:"affected", value:"'libwmf' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);