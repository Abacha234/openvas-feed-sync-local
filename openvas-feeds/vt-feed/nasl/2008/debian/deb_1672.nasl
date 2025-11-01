# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61935");
  script_cve_id("CVE-2008-5187");
  script_tag(name:"creation_date", value:"2008-12-03 17:25:22 +0000 (Wed, 03 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1672)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1672");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1672");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imlib2' package(s) announced via the DSA-1672 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Julien Danjou and Peter De Wachter discovered that a buffer overflow in the XPM loader of Imlib2, a powerful image loading and rendering library, might lead to arbitrary code execution.

For the stable distribution (etch), this problem has been fixed in version 1.3.0.0debian1-4+etch2.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), this problem has been fixed in version 1.4.0-1.2.

We recommend that you upgrade your imlib2 packages.");

  script_tag(name:"affected", value:"'imlib2' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);