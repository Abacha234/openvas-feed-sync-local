# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890867");
  script_cve_id("CVE-2017-6827", "CVE-2017-6828", "CVE-2017-6829", "CVE-2017-6830", "CVE-2017-6831", "CVE-2017-6832", "CVE-2017-6833", "CVE-2017-6834", "CVE-2017-6835", "CVE-2017-6836", "CVE-2017-6837", "CVE-2017-6838", "CVE-2017-6839");
  script_tag(name:"creation_date", value:"2018-01-11 23:00:00 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-867)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-867");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-867");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'audiofile' package(s) announced via the DLA-867 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities has been found in audiofile.

CVE-2017-6829

Allows remote attackers to cause a denial of service (crash) via a crafted file.

CVE-2017-6830 / CVE-2017-6834 / CVE-2017-6831 / CVE-2017-6832 / CVE-2017-6838 / CVE-2017-6839 / CVE-2017-6836 Heap-based buffer overflow in that allows remote attackers to cause a denial of service (crash) via a crafted file.

CVE-2017-6833 / CVE-2017-6835 The runPull function allows remote attackers to cause a denial of service (divide-by-zero error and crash) via a crafted file.

CVE-2017-6837

Allows remote attackers to cause a denial of service (crash) via vectors related to a large number of coefficients.

For Debian 7 Wheezy, these problems have been fixed in version 0.3.4-2+deb7u1.

We recommend that you upgrade your audiofile packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'audiofile' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);