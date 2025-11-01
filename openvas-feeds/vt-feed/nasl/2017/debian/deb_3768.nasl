# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703768");
  script_cve_id("CVE-2016-5158", "CVE-2016-5159", "CVE-2016-8332", "CVE-2016-9572", "CVE-2016-9573");
  script_tag(name:"creation_date", value:"2017-01-19 23:00:00 +0000 (Thu, 19 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 19:57:00 +0000 (Wed, 09 Sep 2020)");

  script_name("Debian: Security Advisory (DSA-3768)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3768");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3768");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg2' package(s) announced via the DSA-3768 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in OpenJPEG, a JPEG 2000 image compression / decompression library, may result in denial of service or the execution of arbitrary code if a malformed JPEG 2000 file is processed.

For the stable distribution (jessie), these problems have been fixed in version 2.1.0-2+deb8u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openjpeg2 packages.");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);