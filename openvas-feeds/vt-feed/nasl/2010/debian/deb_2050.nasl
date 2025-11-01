# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67403");
  script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_tag(name:"creation_date", value:"2010-06-03 20:55:24 +0000 (Thu, 03 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2050");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2050");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdegraphics' package(s) announced via the DSA-2050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in KPDF, a PDF viewer for KDE, which allow the execution of arbitrary code or denial of service if a user is tricked into opening a crafted PDF document.

For the stable distribution (lenny), these problems have been fixed in version 4:3.5.9-3+lenny3.

The unstable distribution (sid) no longer contains kpdf. It's replacement, Okular, links against the poppler PDF library.

We recommend that you upgrade your kdegraphics packages.");

  script_tag(name:"affected", value:"'kdegraphics' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);