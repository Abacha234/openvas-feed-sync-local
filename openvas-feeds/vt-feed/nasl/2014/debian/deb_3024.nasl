# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703024");
  script_cve_id("CVE-2014-5270");
  script_tag(name:"creation_date", value:"2014-09-10 22:00:00 +0000 (Wed, 10 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3024");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3024");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DSA-3024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Genkin, Pipman and Tromer discovered a side-channel attack on Elgamal encryption subkeys ( CVE-2014-5270).

In addition, this update hardens GnuPG's behaviour when treating keyserver responses, GnuPG now filters keyserver responses to only accepts those keyid's actually requested by the user.

For the stable distribution (wheezy), this problem has been fixed in version 1.4.12-7+deb7u6.

For the testing (jessie) and unstable distribution (sid), this problem has been fixed in version 1.4.18-4.

We recommend that you upgrade your gnupg packages.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);