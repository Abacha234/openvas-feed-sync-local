# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53629");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-340");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-340");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'x-face-el' package(s) announced via the DSA-340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NOTE: due to a combination of administrative problems, this advisory was erroneously released with the identifier 'DSA-338-1'. DSA-338-1 correctly refers to an earlier advisory regarding proftpd.

x-face-el, a decoder for images included inline in X-Face email headers, does not take appropriate security precautions when creating temporary files. This bug could potentially be exploited to overwrite arbitrary files with the privileges of the user running Emacs and x-face-el, potentially with contents supplied by the attacker.

For the stable distribution (woody) this problem has been fixed in version 1.3.6.19-1woody1.

For the unstable distribution (sid) this problem has been fixed in version 1.3.6.23-1.

We recommend that you update your x-face-el package.");

  script_tag(name:"affected", value:"'x-face-el' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);