# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703408");
  script_cve_id("CVE-2015-8313");
  script_tag(name:"creation_date", value:"2015-11-30 23:00:00 +0000 (Mon, 30 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-09 17:47:00 +0000 (Thu, 09 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3408");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3408");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls26' package(s) announced via the DSA-3408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GnuTLS, a library implementing the TLS and SSL protocols, incorrectly validates the first byte of padding in CBC modes. A remote attacker can possibly take advantage of this flaw to perform a padding oracle attack.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.12.20-8+deb7u4.

We recommend that you upgrade your gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);