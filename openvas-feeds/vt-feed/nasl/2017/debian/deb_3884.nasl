# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703884");
  script_cve_id("CVE-2017-7507");
  script_tag(name:"creation_date", value:"2017-06-15 22:00:00 +0000 (Thu, 15 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3884)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3884");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3884");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls28' package(s) announced via the DSA-3884 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hubert Kario discovered that GnuTLS, a library implementing the TLS and SSL protocols, does not properly decode a status response TLS extension, allowing a remote attacker to cause an application using the GnuTLS library to crash (denial of service).

For the stable distribution (jessie), this problem has been fixed in version 3.3.8-6+deb8u6.

For the upcoming stable distribution (stretch), this problem has been fixed in version 3.5.8-5+deb9u1.

For the unstable distribution (sid), this problem has been fixed in version 3.5.8-6.

We recommend that you upgrade your gnutls28 packages.");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);