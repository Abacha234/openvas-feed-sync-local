# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704442");
  script_cve_id("CVE-2019-3839");
  script_tag(name:"creation_date", value:"2019-05-13 02:00:05 +0000 (Mon, 13 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 14:31:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4442)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4442");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4442");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ghostscript");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups-filters' package(s) announced via the DSA-4442 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in Ghostscript, the GPL PostScript/PDF interpreter, which may result in denial of service or the execution of arbitrary code if a malformed Postscript file is processed (despite the -dSAFER sandbox being enabled).

For the stable distribution (stretch), this problem has been fixed in version 9.26a~dfsg-0+deb9u3.

We recommend that you upgrade your ghostscript packages.

For the detailed security status of ghostscript please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);