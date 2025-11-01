# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64922");
  script_cve_id("CVE-2009-2369");
  script_tag(name:"creation_date", value:"2009-09-21 21:13:00 +0000 (Mon, 21 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1890)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1890");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1890");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wxwidgets2.6, wxwidgets2.8, wxwindows2.4' package(s) announced via the DSA-1890 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tielei Wang has discovered an integer overflow in wxWidgets, the wxWidgets Cross-platform C++ GUI toolkit, which allows the execution of arbitrary code via a crafted JPEG file.

For the oldstable distribution (etch), this problem has been fixed in version 2.4.5.1.1+etch1 for wxwindows2.4 and version 2.6.3.2.1.5+etch1 for wxwidgets2.6.

For the stable distribution (lenny), this problem has been fixed in version 2.6.3.2.2-3+lenny1 for wxwidgets2.6 and version 2.8.7.1-1.1+lenny1 for wxwidgets2.8.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.8.7.1-2 for wxwidgets2.8 and will be fixed soon for wxwidgets2.6.

We recommend that you upgrade your wxwidgets packages.");

  script_tag(name:"affected", value:"'wxwidgets2.6, wxwidgets2.8, wxwindows2.4' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);