# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703612");
  script_cve_id("CVE-2016-4994");
  script_tag(name:"creation_date", value:"2016-06-30 22:00:00 +0000 (Thu, 30 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 19:07:00 +0000 (Mon, 07 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-3612)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3612");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3612");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gimp' package(s) announced via the DSA-3612 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Shmuel H discovered that GIMP, the GNU Image Manipulation Program, is prone to a use-after-free vulnerability in the channel and layer properties parsing process when loading a XCF file. An attacker can take advantage of this flaw to potentially execute arbitrary code with the privileges of the user running GIMP if a specially crafted XCF file is processed.

For the stable distribution (jessie), this problem has been fixed in version 2.8.14-1+deb8u1.

We recommend that you upgrade your gimp packages.");

  script_tag(name:"affected", value:"'gimp' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);