# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703774");
  script_cve_id("CVE-2016-10165");
  script_tag(name:"creation_date", value:"2017-01-28 23:00:00 +0000 (Sat, 28 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3774)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3774");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3774");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lcms2' package(s) announced via the DSA-3774 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ibrahim M. El-Sayed discovered an out-of-bounds heap read vulnerability in the function Type_MLU_Read in lcms2, the Little CMS 2 color management library, which can be triggered by an image with a specially crafted ICC profile and leading to a heap memory leak or denial-of-service for applications using the lcms2 library.

For the stable distribution (jessie), this problem has been fixed in version 2.6-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem has been fixed in version 2.8-4.

We recommend that you upgrade your lcms2 packages.");

  script_tag(name:"affected", value:"'lcms2' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);